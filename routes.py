import csv
import io
import ipaddress
from datetime import datetime, timezone

from flask import (
    Blueprint,
    jsonify,
    render_template,
    Response,
    request,
    redirect,
    url_for,
    session,
)

from .db import get_db
from .detection import process_event
from .log_analyzer import analyze_log
from .ioc_tracker import extract_iocs_from_event
from .threat_intel import enrich_iocs
from .ticketing import generate_ticket_pdf


bp = Blueprint("main", __name__)


# ============================================================
# AUTH HELPERS
# ============================================================

def get_current_user_id():
    return session.get("user_id")


def login_required():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    return None


# ============================================================
# PAGINATION HELPERS
# ============================================================

def parse_pagination():
    """
    Parse page and per_page safely.

    Default:
        page = 1
        per_page = 25

    Maximum:
        per_page = 100
    """

    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1

    try:
        per_page = int(request.args.get("per_page", 25))
    except (TypeError, ValueError):
        per_page = 25

    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)

    offset = (page - 1) * per_page

    return page, per_page, offset


def pagination_requested(filter_names=None):
    """
    Keep old API responses compatible.

    Without page/per_page/filter:
        API returns the old plain list.

    With pagination/filter parameters:
        API returns items + pagination metadata.
    """

    if "page" in request.args:
        return True

    if "per_page" in request.args:
        return True

    if filter_names:
        for name in filter_names:
            if request.args.get(name):
                return True

    return False


def build_pagination(total, page, per_page):
    pages = (
        (total + per_page - 1) // per_page
        if total > 0
        else 0
    )

    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_next": page < pages,
        "has_previous": page > 1 and pages > 0,
    }


def paginated_response(
    items,
    total,
    page,
    per_page,
):
    return {
        "items": items,
        "pagination": build_pagination(
            total,
            page,
            per_page,
        ),
    }


# ============================================================
# IOC PERSISTENCE
# ============================================================

def persist_iocs(db, iocs, event_id, user_id, timestamp):
    """Persist extracted IOCs and link them to the current event/user."""

    persisted = []

    for ioc in iocs or []:
        if not isinstance(ioc, dict):
            continue

        ioc_type = str(ioc.get("ioc_type", "")).strip().lower()
        value = str(ioc.get("value", "")).strip()

        if not ioc_type or not value:
            continue

        db.execute(
            """
            INSERT OR IGNORE INTO iocs (
                ioc_type,
                value,
                first_seen,
                last_seen,
                status,
                event_count
            )
            VALUES (?, ?, ?, ?, 'ACTIVE', 0)
            """,
            (ioc_type, value, timestamp, timestamp),
        )

        db.execute(
            """
            UPDATE iocs
            SET last_seen = ?
            WHERE value = ?
            """,
            (timestamp, value),
        )

        row = db.execute(
            """
            SELECT ioc_id
            FROM iocs
            WHERE value = ?
            """,
            (value,),
        ).fetchone()

        if row is None:
            continue

        ioc_id = row["ioc_id"]

        db.execute(
            """
            INSERT OR IGNORE INTO ioc_events (
                ioc_id,
                event_id,
                user_id,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (ioc_id, event_id, user_id, timestamp),
        )

        count_row = db.execute(
            """
            SELECT COUNT(*) AS event_count
            FROM ioc_events
            WHERE ioc_id = ?
            """,
            (ioc_id,),
        ).fetchone()

        db.execute(
            """
            UPDATE iocs
            SET event_count = ?
            WHERE ioc_id = ?
            """,
            (int(count_row["event_count"]), ioc_id),
        )

        item = dict(ioc)
        item["ioc_id"] = ioc_id
        item["event_id"] = event_id
        item["user_id"] = user_id
        persisted.append(item)

    return persisted


# ============================================================
# PAGE ROUTES
# ============================================================

@bp.get("/")
def home():
    return redirect(url_for("auth.login"))


@bp.get("/input")
def input_page():
    auth_check = login_required()

    if auth_check:
        return auth_check

    return render_template("input.html")


@bp.get("/dashboard")
def dashboard():
    auth_check = login_required()

    if auth_check:
        return auth_check

    return render_template("dashboard.html")


# ============================================================
# SUMMARY API
# ============================================================

@bp.get("/api/summary")
def api_summary():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    row = db.execute(
        """
        SELECT
            COUNT(*) AS total,

            COALESCE(
                SUM(
                    CASE
                        WHEN severity = 'CRITICAL'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS critical,

            COALESCE(
                SUM(
                    CASE
                        WHEN severity = 'HIGH'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS high,

            COALESCE(
                SUM(
                    CASE
                        WHEN severity = 'MEDIUM'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS medium,

            COALESCE(
                SUM(
                    CASE
                        WHEN status = 'OPEN'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS open

        FROM alerts
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()

    return jsonify(dict(row))


# ============================================================
# ALERTS API
# ============================================================

@bp.get("/api/alerts")
def get_alerts():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    filter_names = [
        "severity",
        "status",
        "rule_name",
        "source_ip",
    ]

    use_pagination = pagination_requested(
        filter_names
    )

    where = [
        "user_id = ?"
    ]

    params = [
        user_id
    ]

    severity = request.args.get(
        "severity",
        ""
    ).strip()

    status = request.args.get(
        "status",
        ""
    ).strip()

    rule_name = request.args.get(
        "rule_name",
        ""
    ).strip()

    source_ip = request.args.get(
        "source_ip",
        ""
    ).strip()

    if severity:
        where.append(
            "severity = ?"
        )
        params.append(
            severity
        )

    if status:
        where.append(
            "status = ?"
        )
        params.append(
            status
        )

    if rule_name:
        where.append(
            "rule_name = ?"
        )
        params.append(
            rule_name
        )

    if source_ip:
        where.append(
            "source_ip = ?"
        )
        params.append(
            source_ip
        )

    where_sql = " AND ".join(where)

    count_row = db.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM alerts
        WHERE {where_sql}
        """,
        tuple(params),
    ).fetchone()

    total = int(
        count_row["total"]
    )

    if use_pagination:

        page, per_page, offset = (
            parse_pagination()
        )

        rows = db.execute(
            f"""
            SELECT *
            FROM alerts
            WHERE {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params)
            + (
                per_page,
                offset,
            ),
        ).fetchall()

        items = [
            dict(row)
            for row in rows
        ]

        return jsonify(
            paginated_response(
                items,
                total,
                page,
                per_page,
            )
        )

    rows = db.execute(
        f"""
        SELECT *
        FROM alerts
        WHERE {where_sql}
        ORDER BY id DESC
        """,
        tuple(params),
    ).fetchall()

    return jsonify(
        [
            dict(row)
            for row in rows
        ]
    )


# ============================================================
# SINGLE ALERT API
# ============================================================

@bp.get("/api/alerts/<int:alert_id>")
def get_alert(alert_id):
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    row = db.execute(
        """
        SELECT *
        FROM alerts
        WHERE id = ?
          AND user_id = ?
        """,
        (
            alert_id,
            user_id,
        ),
    ).fetchone()

    if row is None:
        return jsonify({
            "error": "Alert not found"
        }), 404

    return jsonify(
        dict(row)
    )


# ============================================================
# EVENTS API - GET
# ============================================================

@bp.get("/api/events")
def get_events():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    filter_names = [
        "event_type",
        "source_ip",
        "status",
        "username",
    ]

    use_pagination = pagination_requested(
        filter_names
    )

    where = [
        "user_id = ?"
    ]

    params = [
        user_id
    ]

    event_type = request.args.get(
        "event_type",
        ""
    ).strip()

    source_ip = request.args.get(
        "source_ip",
        ""
    ).strip()

    status = request.args.get(
        "status",
        ""
    ).strip()

    username = request.args.get(
        "username",
        ""
    ).strip()

    if event_type:
        where.append(
            "event_type = ?"
        )
        params.append(
            event_type
        )

    if source_ip:
        where.append(
            "source_ip = ?"
        )
        params.append(
            source_ip
        )

    if status:
        where.append(
            "status = ?"
        )
        params.append(
            status
        )

    if username:
        where.append(
            "username = ?"
        )
        params.append(
            username
        )

    where_sql = " AND ".join(where)

    count_row = db.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM events
        WHERE {where_sql}
        """,
        tuple(params),
    ).fetchone()

    total = int(
        count_row["total"]
    )

    if use_pagination:

        page, per_page, offset = (
            parse_pagination()
        )

        rows = db.execute(
            f"""
            SELECT *
            FROM events
            WHERE {where_sql}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params)
            + (
                per_page,
                offset,
            ),
        ).fetchall()

        items = [
            dict(row)
            for row in rows
        ]

        return jsonify(
            paginated_response(
                items,
                total,
                page,
                per_page,
            )
        )

    rows = db.execute(
        f"""
        SELECT *
        FROM events
        WHERE {where_sql}
        ORDER BY timestamp DESC, id DESC
        """,
        tuple(params),
    ).fetchall()

    return jsonify(
        [
            dict(row)
            for row in rows
        ]
    )


# ============================================================
# EVENTS API - POST
# ============================================================

@bp.post("/api/events")
def create_event():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()

    data = request.get_json(
        silent=True
    ) or {}

    event_type = str(
        data.get(
            "event_type",
            ""
        )
    ).strip()

    source_ip = str(
        data.get(
            "source_ip",
            ""
        )
    ).strip()

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()

    destination_port = data.get(
        "destination_port"
    )

    # The Input page sends the log text as "message".
    # Also accept "raw_log" for direct/API clients.
    raw_log = str(
        data.get("raw_log")
        or data.get("message")
        or ""
    ).strip()

    if not event_type:
        return jsonify({
            "error": "event_type is required"
        }), 400

    if not source_ip:
        return jsonify({
            "error": "source_ip is required"
        }), 400

    try:
        ipaddress.ip_address(
            source_ip
        )
    except ValueError:
        return jsonify({
            "error": "Invalid source_ip"
        }), 400

    if destination_port not in (
        None,
        "",
    ):

        try:
            destination_port = int(
                destination_port
            )

        except (
            TypeError,
            ValueError,
        ):
            return jsonify({
                "error": "Invalid destination_port"
            }), 400

        if not (
            1
            <= destination_port
            <= 65535
        ):
            return jsonify({
                "error": (
                    "destination_port must "
                    "be between 1 and 65535"
                )
            }), 400

    event = {
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "destination_port": destination_port,
        "raw_log": raw_log,
    }

    # --------------------------------------------------------
    # LOG ANALYSIS
    # --------------------------------------------------------

    # IOC extraction and detection operate on the normalized
    # event message. The input API uses raw_log, so expose it
    # as message before running the analyzer.
    if not event.get("message") and raw_log:
        event["message"] = str(raw_log)

    try:
        log_analysis = analyze_log(event)

    except Exception:
        log_analysis = {}

    if isinstance(log_analysis, dict):
        event.update(log_analysis)

    event_type = str(event.get("event_type", event_type)).strip()
    source_ip = str(event.get("source_ip", source_ip)).strip()
    username = str(event.get("username", username)).strip()
    destination_port = event.get("destination_port", destination_port)

    # --------------------------------------------------------
    # INSERT EVENT
    # --------------------------------------------------------

    db = get_db()

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    cursor = db.execute(
        """
        INSERT INTO events (
            user_id,
            event_type,
            source_ip,
            username,
            destination_port,
            status,
            message,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            event_type,
            source_ip,
            username,
            destination_port,
            event.get("status", ""),
            event.get("message", str(raw_log or "")),
            timestamp,
        ),
    )

    event_id = cursor.lastrowid

    event["id"] = event_id
    event["event_id"] = event_id
    event["user_id"] = user_id
    event["timestamp"] = timestamp

    # --------------------------------------------------------
    # IOC EXTRACTION
    # --------------------------------------------------------

    try:
        # Extract IOCs from both the normalized log message and
        # the source IP field. This guarantees that a valid
        # source IP is tracked even when the user does not repeat
        # it inside the message.
        ioc_event = dict(event)
        ioc_event["message"] = " ".join(
            part for part in (
                event.get("message", ""),
                event.get("source_ip", ""),
            )
            if part
        )

        ioc_result = extract_iocs_from_event(ioc_event)

        if isinstance(ioc_result, dict):
            iocs = ioc_result.get("iocs", [])
        else:
            iocs = ioc_result or []

    except Exception:
        iocs = []

    iocs = persist_iocs(
        db,
        iocs,
        event_id,
        user_id,
        timestamp,
    )

    # --------------------------------------------------------
    # THREAT INTEL
    # --------------------------------------------------------

    try:
        threat_intel_matches = enrich_iocs(
            iocs
        )

    except Exception:
        threat_intel_matches = []

    if threat_intel_matches is None:
        threat_intel_matches = []

    # --------------------------------------------------------
    # DETECTION ENGINE
    # --------------------------------------------------------

    detection_result = process_event(
        event,
        user_id,
        threat_intel_matches,
    )

    db.commit()

    return jsonify({
        "success": True,

        "event_id": event_id,

        "detected": detection_result.get(
            "detected",
            False,
        ),

        "alert_id": detection_result.get(
            "alert_id"
        ),

        "alert": detection_result.get(
            "alert"
        ),

        "ticket": detection_result.get(
            "ticket"
        ),

        "alert_ids": detection_result.get(
            "alert_ids",
            [],
        ),

        "alerts": detection_result.get(
            "alerts",
            [],
        ),

        "tickets": detection_result.get(
            "tickets",
            [],
        ),

        "ioc_count": len(iocs),

        "iocs": iocs,

        "threat_intel_matches": (
            threat_intel_matches
        ),

        "threat_intel_match_count": len(
            threat_intel_matches
        ),

        "message": (
            "Security event processed "
            "successfully"
        ),
    }), 201


# ============================================================
# IOC API
# ============================================================

@bp.get("/api/iocs")
def get_iocs():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    filter_names = [
        "ioc_type",
        "status",
        "value",
    ]

    use_pagination = pagination_requested(
        filter_names
    )

    where = [
        "ie.user_id = ?"
    ]

    params = [
        user_id
    ]

    ioc_type = request.args.get(
        "ioc_type",
        ""
    ).strip()

    status = request.args.get(
        "status",
        ""
    ).strip()

    value = request.args.get(
        "value",
        ""
    ).strip()

    if ioc_type:
        where.append("i.ioc_type = ?")
        params.append(ioc_type)

    if status:
        where.append("i.status = ?")
        params.append(status)

    if value:
        where.append("i.value = ?")
        params.append(value)

    where_sql = " AND ".join(where)

    count_row = db.execute(
        f"""
        SELECT COUNT(DISTINCT i.ioc_id) AS total
        FROM iocs i
        JOIN ioc_events ie
          ON ie.ioc_id = i.ioc_id
        WHERE {where_sql}
        """,
        tuple(params),
    ).fetchone()

    total = int(count_row["total"])

    select_sql = f"""
        SELECT DISTINCT
            i.ioc_id,
            i.ioc_type,
            i.value,
            i.first_seen,
            i.last_seen,
            i.status,
            i.event_count
        FROM iocs i
        JOIN ioc_events ie
          ON ie.ioc_id = i.ioc_id
        WHERE {where_sql}
        ORDER BY i.ioc_id DESC
    """

    if use_pagination:
        page, per_page, offset = parse_pagination()

        rows = db.execute(
            select_sql + " LIMIT ? OFFSET ?",
            tuple(params) + (per_page, offset),
        ).fetchall()

        items = [dict(row) for row in rows]

        for item in items:
            item["id"] = item["ioc_id"]
            item["type"] = item["ioc_type"]
            item["created_at"] = item["first_seen"]
            item["source"] = "Local IOC Tracker"

        return jsonify(
            paginated_response(
                items,
                total,
                page,
                per_page,
            )
        )

    rows = db.execute(
        select_sql,
        tuple(params),
    ).fetchall()

    items = [dict(row) for row in rows]

    for item in items:
        item["id"] = item["ioc_id"]
        item["type"] = item["ioc_type"]
        item["created_at"] = item["first_seen"]
        item["source"] = "Local IOC Tracker"

    return jsonify(items)


# ============================================================
# IOC SUMMARY
# ============================================================

@bp.get("/api/iocs/summary")
def ioc_summary():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    rows = db.execute(
        """
        SELECT
            i.ioc_type,
            COUNT(DISTINCT i.ioc_id) AS count
        FROM iocs i
        JOIN ioc_events ie
          ON ie.ioc_id = i.ioc_id
        WHERE ie.user_id = ?
        GROUP BY i.ioc_type
        """,
        (user_id,),
    ).fetchall()

    summary = {
        "total": 0,
        "ip": 0,
        "domain": 0,
        "url": 0,
        "email": 0,
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
    }

    for row in rows:
        ioc_type = str(row["ioc_type"] or "").lower()
        count = int(row["count"] or 0)

        if ioc_type in summary:
            summary[ioc_type] = count

        summary["total"] += count

    return jsonify(summary)


# ============================================================
# TICKETS API - GET
# ============================================================

@bp.get("/api/tickets")
def get_tickets():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    filter_names = [
        "status",
        "severity",
        "priority",
        "assignee",
    ]

    use_pagination = pagination_requested(
        filter_names
    )

    where = [
        "user_id = ?"
    ]

    params = [
        user_id
    ]

    status = request.args.get(
        "status",
        ""
    ).strip()

    severity = request.args.get(
        "severity",
        ""
    ).strip()

    priority = request.args.get(
        "priority",
        ""
    ).strip()

    assignee = request.args.get(
        "assignee",
        ""
    ).strip()

    if status:
        where.append(
            "status = ?"
        )
        params.append(
            status
        )

    if severity:
        where.append(
            "severity = ?"
        )
        params.append(
            severity
        )

    if priority:
        where.append(
            "priority = ?"
        )
        params.append(
            priority
        )

    if assignee:
        where.append(
            "assignee = ?"
        )
        params.append(
            assignee
        )

    where_sql = " AND ".join(where)

    count_row = db.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM tickets
        WHERE {where_sql}
        """,
        tuple(params),
    ).fetchone()

    total = int(
        count_row["total"]
    )

    if use_pagination:

        page, per_page, offset = (
            parse_pagination()
        )

        rows = db.execute(
            f"""
            SELECT *
            FROM tickets
            WHERE {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params)
            + (
                per_page,
                offset,
            ),
        ).fetchall()

        items = [
            dict(row)
            for row in rows
        ]

        return jsonify(
            paginated_response(
                items,
                total,
                page,
                per_page,
            )
        )

    rows = db.execute(
        f"""
        SELECT *
        FROM tickets
        WHERE {where_sql}
        ORDER BY id DESC
        """,
        tuple(params),
    ).fetchall()

    return jsonify(
        [
            dict(row)
            for row in rows
        ]
    )


# ============================================================
# SINGLE TICKET
# ============================================================

@bp.get("/api/tickets/<int:ticket_id>")
def get_ticket(ticket_id):
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    row = db.execute(
        """
        SELECT *
        FROM tickets
        WHERE id = ?
          AND user_id = ?
        """,
        (
            ticket_id,
            user_id,
        ),
    ).fetchone()

    if row is None:
        return jsonify({
            "error": "Ticket not found"
        }), 404

    return jsonify(
        dict(row)
    )


# ============================================================
# UPDATE TICKET STATUS
# ============================================================

@bp.patch("/api/tickets/<int:ticket_id>")
def update_ticket(ticket_id):
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()

    data = request.get_json(
        silent=True
    ) or {}

    status = str(
        data.get(
            "status",
            ""
        )
    ).strip().upper()

    allowed_statuses = {
        "OPEN",
        "IN_PROGRESS",
        "RESOLVED",
        "CLOSED",
    }

    if status not in allowed_statuses:
        return jsonify({
            "error": "Invalid status",
            "allowed": sorted(
                allowed_statuses
            ),
        }), 400

    db = get_db()

    ticket = db.execute(
        """
        SELECT id
        FROM tickets
        WHERE id = ?
          AND user_id = ?
        """,
        (
            ticket_id,
            user_id,
        ),
    ).fetchone()

    if ticket is None:
        return jsonify({
            "error": "Ticket not found"
        }), 404

    db.execute(
        """
        UPDATE tickets
        SET status = ?
        WHERE id = ?
          AND user_id = ?
        """,
        (
            status,
            ticket_id,
            user_id,
        ),
    )

    db.commit()

    updated = db.execute(
        """
        SELECT *
        FROM tickets
        WHERE id = ?
          AND user_id = ?
        """,
        (
            ticket_id,
            user_id,
        ),
    ).fetchone()

    return jsonify({
        "success": True,
        "ticket": dict(updated),
    })


# ============================================================
# TICKET PDF
# ============================================================

@bp.get("/api/tickets/<int:ticket_id>/pdf")
def ticket_pdf(ticket_id):
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    ticket = db.execute(
        """
        SELECT *
        FROM tickets
        WHERE id = ?
          AND user_id = ?
        """,
        (
            ticket_id,
            user_id,
        ),
    ).fetchone()

    if ticket is None:
        return jsonify({
            "error": "Ticket not found"
        }), 404

    try:
        pdf_bytes = generate_ticket_pdf(
            dict(ticket)
        )

    except Exception as exc:
        return jsonify({
            "error": (
                "Failed to generate ticket PDF"
            ),
            "details": str(exc),
        }), 500

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                "attachment; "
                f"filename=soc_ticket_{ticket_id}.pdf"
            )
        },
    )


# ============================================================
# CSV REPORT
# ============================================================

@bp.get("/api/report.csv")
def report_csv():
    auth_check = login_required()

    if auth_check:
        return auth_check

    user_id = get_current_user_id()
    db = get_db()

    rows = db.execute(
        """
        SELECT
            id,
            severity,
            status,
            rule_name,
            source_ip,
            created_at
        FROM alerts
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,),
    ).fetchall()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Severity",
        "Status",
        "Rule Name",
        "Source IP",
        "Created At",
    ])

    for row in rows:
        writer.writerow([
            row["id"],
            row["severity"],
            row["status"],
            row["rule_name"],
            row["source_ip"],
            row["created_at"],
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; "
                "filename=soc_report.csv"
            )
        }
    )