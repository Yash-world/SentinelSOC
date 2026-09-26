
from datetime import datetime, timezone, timedelta
import secrets

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from .db import get_db


auth_bp = Blueprint("auth", __name__)


# =========================================================
# SERVER INSTANCE
# =========================================================
# A new value is created every time Flask starts.
# Old login sessions will therefore be treated as invalid.
# =========================================================

SERVER_INSTANCE_ID = secrets.token_urlsafe(32)


def reset_stale_session():
    """Clear a session created by an older Flask run."""

    if (
        "user_id" in session
        and session.get("server_instance") != SERVER_INSTANCE_ID
    ):
        session.clear()


# =========================================================
# BRUTE FORCE DETECTION SETTINGS
# =========================================================

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5


# =========================================================
# RECORD FAILED LOGIN
# =========================================================

def record_failed_login(user_id, email, source_ip):
    """
    Store a failed login attempt and determine whether
    the brute-force threshold has been reached.

    Detection rule:

        5 or more failed logins
        from the same source IP
        within 5 minutes
    """

    db = get_db()

    now = datetime.now(timezone.utc)

    cutoff = (
        now
        - timedelta(
            minutes=BRUTE_FORCE_WINDOW_MINUTES
        )
    )

    # -----------------------------------------------------
    # Record failed login
    # -----------------------------------------------------

    db.execute(
        """
        INSERT INTO auth_failures (
            user_id,
            attempted_email,
            source_ip,
            attempted_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            user_id,
            email,
            source_ip,
            now.isoformat(),
        ),
    )

    # -----------------------------------------------------
    # Count recent failures from same IP
    # -----------------------------------------------------

    row = db.execute(
        """
        SELECT COUNT(*) AS failure_count
        FROM auth_failures
        WHERE source_ip = ?
          AND attempted_at >= ?
        """,
        (
            source_ip,
            cutoff.isoformat(),
        ),
    ).fetchone()

    failure_count = row["failure_count"]

    db.commit()

    return failure_count


# =========================================================
# CREATE BRUTE FORCE ALERT
# =========================================================

def create_brute_force_alert(
    source_ip,
    email,
    failure_count,
    user_id=None,
):
    """
    Create a HIGH severity brute-force alert after
    the threshold is reached.

    Duplicate alerts are prevented within the same
    five-minute detection window.
    """

    db = get_db()

    # -----------------------------------------------------
    # Check whether an alert already exists
    # -----------------------------------------------------

    existing_alert = db.execute(
        """
        SELECT id
        FROM alerts
        WHERE rule_name = ?
          AND source_ip = ?
          AND created_at >= ?
        LIMIT 1
        """,
        (
            "BRUTE_FORCE_LOGIN",
            source_ip,
            (
                datetime.now(timezone.utc)
                - timedelta(
                    minutes=BRUTE_FORCE_WINDOW_MINUTES
                )
            ).isoformat(),
        ),
    ).fetchone()

    # Do not create duplicate alerts
    if existing_alert:
        return existing_alert["id"]

    # -----------------------------------------------------
    # Create alert
    # -----------------------------------------------------

    now = datetime.now(timezone.utc).isoformat()

    description = (
        f"{failure_count} failed login attempts "
        f"were detected from source IP {source_ip} "
        f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes."
    )

    if email:
        description += (
            f" Targeted account: {email}."
        )

    cursor = db.execute(
        """
        INSERT INTO alerts (
            user_id,
            created_at,
            severity,
            rule_name,
            title,
            description,
            source_ip,
            mitre_id,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            now,
            "HIGH",
            "BRUTE_FORCE_LOGIN",
            "Brute Force Login Detected",
            description,
            source_ip,
            "T1110",
            "OPEN",
        ),
    )

    db.commit()

    return cursor.lastrowid


# =========================================================
# LOGIN PAGE
# =========================================================

@auth_bp.get("/login")
def login():

    reset_stale_session()

    if "user_id" in session:
        return redirect(
            url_for("main.input_page")
        )

    return render_template("login.html")


# =========================================================
# LOGIN USER
# =========================================================

@auth_bp.post("/login")
def login_user():

    reset_stale_session()

    email = (
        request.form
        .get("email", "")
        .strip()
        .lower()
    )

    password = request.form.get(
        "password",
        ""
    )

    # -----------------------------------------------------
    # Get source IP
    # -----------------------------------------------------

    source_ip = (
        request.remote_addr
        or "unknown"
    )

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    if not email or not password:

        flash(
            "Please enter your email and password.",
            "error",
        )

        return redirect(
            url_for("auth.login")
        )

    db = get_db()

    # -----------------------------------------------------
    # Find user
    # -----------------------------------------------------

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,),
    ).fetchone()

    # -----------------------------------------------------
    # Unknown user
    # -----------------------------------------------------
    # We still record the failure.
    # This prevents attackers from bypassing
    # brute-force detection by targeting non-existing
    # usernames/emails.
    # -----------------------------------------------------

    if user is None:

        failure_count = record_failed_login(
            user_id=None,
            email=email,
            source_ip=source_ip,
        )

        if (
            failure_count
            >= BRUTE_FORCE_THRESHOLD
        ):

            create_brute_force_alert(
                source_ip=source_ip,
                email=email,
                failure_count=failure_count,
                user_id=None,
            )

        flash(
            "Invalid email or password.",
            "error",
        )

        return redirect(
            url_for("auth.login")
        )

    # -----------------------------------------------------
    # Check password
    # -----------------------------------------------------

    password_valid = check_password_hash(
        user["password_hash"],
        password,
    )

    # -----------------------------------------------------
    # Wrong password
    # -----------------------------------------------------

    if not password_valid:

        failure_count = record_failed_login(
            user_id=user["id"],
            email=email,
            source_ip=source_ip,
        )

        # -------------------------------------------------
        # Threshold reached
        # -------------------------------------------------

        if (
            failure_count
            >= BRUTE_FORCE_THRESHOLD
        ):

            create_brute_force_alert(
                source_ip=source_ip,
                email=email,
                failure_count=failure_count,
                user_id=user["id"],
            )

        flash(
            "Invalid email or password.",
            "error",
        )

        return redirect(
            url_for("auth.login")
        )

    # =====================================================
    # SUCCESSFUL LOGIN
    # =====================================================

    session.clear()

    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session["name"] = user["name"]

    # Mark session as belonging to this server run
    session["server_instance"] = (
        SERVER_INSTANCE_ID
    )

    # -----------------------------------------------------
    # LOGIN -> INPUT
    # -----------------------------------------------------

    return redirect(
        url_for("main.input_page")
    )


# =========================================================
# REGISTER PAGE
# =========================================================

@auth_bp.get("/register")
def register():

    reset_stale_session()

    if "user_id" in session:
        return redirect(
            url_for("main.input_page")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# REGISTER USER
# =========================================================

@auth_bp.post("/register")
def register_user():

    name = (
        request.form
        .get("name", "")
        .strip()
    )

    email = (
        request.form
        .get("email", "")
        .strip()
        .lower()
    )

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = (
        request.form
        .get("confirm_password", "")
    )

    # -----------------------------------------------------
    # Name validation
    # -----------------------------------------------------

    if not name:

        flash(
            "Please enter your name.",
            "error",
        )

        return redirect(
            url_for("auth.register")
        )

    # -----------------------------------------------------
    # Email validation
    # -----------------------------------------------------

    if not email:

        flash(
            "Please enter your email.",
            "error",
        )

        return redirect(
            url_for("auth.register")
        )

    # -----------------------------------------------------
    # Password validation
    # -----------------------------------------------------

    if not password:

        flash(
            "Please enter a password.",
            "error",
        )

        return redirect(
            url_for("auth.register")
        )

    if len(password) < 8:

        flash(
            "Password must be at least 8 characters.",
            "error",
        )

        return redirect(
            url_for("auth.register")
        )

    # -----------------------------------------------------
    # Confirm password
    # -----------------------------------------------------

    if password != confirm_password:

        flash(
            "Passwords do not match.",
            "error",
        )

        return redirect(
            url_for("auth.register")
        )

    db = get_db()

    # -----------------------------------------------------
    # Check existing account
    # -----------------------------------------------------

    existing_user = db.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        """,
        (email,),
    ).fetchone()

    if existing_user:

        flash(
            "An account with this email already exists. "
            "Please login.",
            "error",
        )

        return redirect(
            url_for("auth.login")
        )

    # -----------------------------------------------------
    # Hash password
    # -----------------------------------------------------

    password_hash = generate_password_hash(
        password
    )

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    # -----------------------------------------------------
    # Create user
    # -----------------------------------------------------

    db.execute(
        """
        INSERT INTO users (
            email,
            password_hash,
            name,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            email,
            password_hash,
            name,
            created_at,
        ),
    )

    db.commit()

    # -----------------------------------------------------
    # IMPORTANT:
    #
    # Registration does NOT automatically login.
    #
    # REGISTER -> LOGIN -> INPUT -> DASHBOARD
    # -----------------------------------------------------

    flash(
        "Registration successful! Please login.",
        "success",
    )

    return redirect(
        url_for("auth.login")
    )


# =========================================================
# LOGOUT
# =========================================================

@auth_bp.get("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(
        url_for("auth.login")
    )

