
import hashlib
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from threading import Lock
from datetime import datetime, timezone, timedelta

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .db import get_db
from .detection import process_event
from .log_analyzer import analyze_log


connectors_bp = Blueprint("connectors", __name__)
ingestion_bp = Blueprint("ingestion", __name__)


# Authentication failure protection.
_AUTH_FAILURE_LIMIT = 10
_AUTH_FAILURE_WINDOW = 60
_auth_failures = defaultdict(deque)
_auth_lock = Lock()

_last_ingestion_cleanup = 0.0
_cleanup_lock = Lock()


# Temporary one-time token display.
# Tokens are never placed in URLs or client-side session cookies.
# For multi-worker production deployments, use shared server-side storage.
_pending_connector_tokens = {}
_pending_connector_tokens_lock = Lock()


def _record_auth_failure(ip):
    now = time.monotonic()

    with _auth_lock:
        failures = _auth_failures[ip]

        while failures and now - failures[0] >= _AUTH_FAILURE_WINDOW:
            failures.popleft()

        failures.append(now)
        return len(failures) >= _AUTH_FAILURE_LIMIT


def _auth_rate_limited(ip):
    now = time.monotonic()

    with _auth_lock:
        failures = _auth_failures[ip]

        while failures and now - failures[0] >= _AUTH_FAILURE_WINDOW:
            failures.popleft()

        if not failures:
            _auth_failures.pop(ip, None)
            return False

        return len(failures) >= _AUTH_FAILURE_LIMIT


def _clear_auth_failures(ip):
    with _auth_lock:
        _auth_failures.pop(ip, None)


def _cleanup_old_ingestion_state(db):
    global _last_ingestion_cleanup

    now = time.monotonic()

    if now - _last_ingestion_cleanup < 300:
        return

    with _cleanup_lock:
        now = time.monotonic()

        if now - _last_ingestion_cleanup < 300:
            return

        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        db.execute(
            "DELETE FROM ingestion_state WHERE received_at < ?",
            (cutoff,),
        )

        _last_ingestion_cleanup = now


def _now():
    return datetime.now(timezone.utc).isoformat()


def _user_id():
    return session.get("user_id")


def _get_sources(db, user_id):
    return db.execute(
        """
        SELECT
            id,
            name,
            source_type,
            enabled,
            created_at,
            last_seen,
            events_received
        FROM log_sources
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,),
    ).fetchall()


@connectors_bp.get("/connectors")
def connectors_page():
    user_id = _user_id()

    if not user_id:
        return redirect(url_for("auth.login"))

    db = get_db()
    rows = _get_sources(db, user_id)

    # Consume the one-time token display on the next GET.
    with _pending_connector_tokens_lock:
        pending = _pending_connector_tokens.pop(user_id, None)

    new_token = None

    if pending is not None:
        # Only show a token to the user who created its connector.
        source = db.execute(
            """
            SELECT id
            FROM log_sources
            WHERE id = ? AND user_id = ?
            """,
            (pending["source_id"], user_id),
        ).fetchone()

        if source is not None:
            new_token = pending

    response = current_app.make_response(
        render_template(
            "connectors.html",
            sources=rows,
            new_token=new_token,
        )
    )

    # Avoid caching a page containing a bearer token.
    if new_token is not None:
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private"
        )
        response.headers["Pragma"] = "no-cache"

    return response


@connectors_bp.post("/connectors/create")
def create_connector():
    user_id = _user_id()

    if not user_id:
        return redirect(url_for("auth.login"))

    name = (request.form.get("name") or "").strip()[:80]
    source_type = (
        request.form.get("source_type") or ""
    ).strip().lower()

    allowed_types = {"linux", "windows", "syslog", "api"}

    if not name or source_type not in allowed_types:
        return jsonify({
            "error": "Valid name and source type are required."
        }), 400

    raw_token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    db = get_db()

    try:
        cur = db.execute(
            """
            INSERT INTO log_sources
                (
                    user_id,
                    name,
                    source_type,
                    token_hash,
                    enabled,
                    created_at
                )
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (
                user_id,
                name,
                source_type,
                token_hash,
                _now(),
            ),
        )

        source_id = cur.lastrowid
        db.commit()

    except Exception:
        db.rollback()
        current_app.logger.exception(
            "Failed to create SentinelSOC connector"
        )
        return jsonify({
            "error": "Connector creation failed."
        }), 500

    # Store the one-time token display on the server, not in the URL
    # or the Flask signed-cookie session.
    with _pending_connector_tokens_lock:
        _pending_connector_tokens[user_id] = {
            "source_id": source_id,
            "name": name,
            "source_type": source_type,
            "token": raw_token,
        }

    # POST -> Redirect -> GET prevents a browser refresh from
    # resubmitting the connector creation form.
    return redirect(url_for("connectors.connectors_page"))


@connectors_bp.post("/connectors/<int:source_id>/toggle")
def toggle_connector(source_id):
    user_id = _user_id()

    if not user_id:
        return redirect(url_for("auth.login"))

    db = get_db()

    row = db.execute(
        """
        SELECT enabled
        FROM log_sources
        WHERE id = ? AND user_id = ?
        """,
        (source_id, user_id),
    ).fetchone()

    if row is None:
        return jsonify({
            "error": "Connector not found"
        }), 404

    new_enabled = 0 if row["enabled"] else 1

    db.execute(
        """
        UPDATE log_sources
        SET enabled = ?
        WHERE id = ? AND user_id = ?
        """,
        (new_enabled, source_id, user_id),
    )

    db.commit()

    return redirect(url_for("connectors.connectors_page"))


@connectors_bp.post("/connectors/<int:source_id>/revoke")
def revoke_connector(source_id):
    user_id = _user_id()

    if not user_id:
        return redirect(url_for("auth.login"))

    db = get_db()

    db.execute(
        """
        DELETE FROM log_sources
        WHERE id = ? AND user_id = ?
        """,
        (source_id, user_id),
    )

    db.commit()

    # Remove a pending display if its connector is revoked.
    with _pending_connector_tokens_lock:
        pending = _pending_connector_tokens.get(user_id)

        if pending and pending["source_id"] == source_id:
            _pending_connector_tokens.pop(user_id, None)

    return redirect(url_for("connectors.connectors_page"))


@ingestion_bp.post("/api/ingest/<int:source_id>")
def ingest_event(source_id):
    # Per-source bearer token authentication.
    ip = request.remote_addr or "unknown"

    if _auth_rate_limited(ip):
        return jsonify({
            "error": "Too many failed token attempts; retry in 60 seconds."
        }), 429

    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Bearer "):
        _record_auth_failure(ip)
        return jsonify({
            "error": "Bearer token required"
        }), 401

    token = auth[7:].strip()

    if not token or len(token) > 256:
        _record_auth_failure(ip)
        return jsonify({
            "error": "Invalid token"
        }), 401

    db = get_db()

    row = db.execute(
        """
        SELECT *
        FROM log_sources
        WHERE id = ? AND enabled = 1
        """,
        (source_id,),
    ).fetchone()

    if row is None:
        _record_auth_failure(ip)
        return jsonify({
            "error": "Unknown, disabled, or revoked connector"
        }), 401

    supplied_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    if not secrets.compare_digest(
        supplied_hash,
        row["token_hash"],
    ):
        _record_auth_failure(ip)
        return jsonify({
            "error": "Invalid token"
        }), 401

    _clear_auth_failures(ip)
    _cleanup_old_ingestion_state(db)

    # Per-source ingestion rate limit.
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()

    recent = db.execute(
        """
        SELECT COUNT(*) AS n
        FROM ingestion_state
        WHERE source_id = ? AND received_at >= ?
        """,
        (source_id, cutoff),
    ).fetchone()

    if int(recent["n"]) >= 120:
        return jsonify({
            "error": "Connector rate limit exceeded; retry shortly."
        }), 429

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "JSON object required"
        }), 400

    metadata = data.get("metadata")
    metadata_platform = (
        metadata.get("platform", "")
        if isinstance(metadata, dict)
        else ""
    )

    raw_log = str(
        data.get("raw_log") or data.get("message") or ""
    ).strip()

    if not raw_log:
        return jsonify({
            "error": "raw_log is required"
        }), 400

    if len(raw_log) > 16000:
        return jsonify({
            "error": "raw_log exceeds 16000 characters"
        }), 413

    event = {
        "event_type": str(
            data.get("event_type") or "unknown"
        )[:80],

        "platform": str(
            data.get("platform")
            or metadata_platform
            or row["source_type"]
            or "unknown"
        )[:20].lower(),

        "source_ip": str(
            data.get("source_ip") or ""
        )[:64],

        "username": str(
            data.get("username") or ""
        )[:128],

        "destination_port": data.get("destination_port"),

        "status": str(
            data.get("status") or ""
        )[:40],

        "message": raw_log,
        "raw_log": raw_log,

        "timestamp": str(
            data.get("timestamp") or _now()
        )[:128],
    }

    event = analyze_log(event)

    event["source_id"] = source_id
    event["ingestion_mode"] = "automated"

    event_key = str(
        data.get("event_id")
        or hashlib.sha256(
            (
                str(event.get("timestamp"))
                + "\0"
                + raw_log
            ).encode()
        ).hexdigest()
    )[:128]

    try:
        db.execute(
            """
            INSERT INTO ingestion_state
                (source_id, event_key, received_at)
            VALUES (?, ?, ?)
            """,
            (source_id, event_key, _now()),
        )

    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({
            "success": True,
            "duplicate": True,
        }), 200

    timestamp = str(
        event.get("timestamp") or _now()
    )

    cur = db.execute(
        """
        INSERT INTO events
            (
                user_id,
                event_type,
                source_ip,
                username,
                destination_port,
                status,
                message,
                timestamp,
                source_id,
                ingestion_mode
            )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'automated')
        """,
        (
            row["user_id"],
            event.get("event_type") or "unknown",
            event.get("source_ip") or None,
            event.get("username") or None,
            event.get("destination_port"),
            event.get("status") or "",
            raw_log,
            timestamp,
            source_id,
        ),
    )

    event_id = cur.lastrowid

    event.update({
        "id": event_id,
        "event_id": event_id,
        "user_id": row["user_id"],
        "timestamp": timestamp,
    })

    detection = process_event(
        event,
        row["user_id"],
        [],
    )

    db.execute(
        """
        UPDATE log_sources
        SET last_seen = ?,
            events_received = events_received + 1
        WHERE id = ?
        """,
        (_now(), source_id),
    )

    db.commit()

    return jsonify({
        "success": True,
        "event_id": event_id,
        "detected": bool(
            detection.get("detected", False)
        ),
        "alert_id": detection.get("alert_id"),
        "duplicate": False,
    }), 201
