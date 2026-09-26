import sqlite3
import os

from flask import g


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():
    """
    Return the current SQLite database connection.
    One connection is maintained per Flask request.
    """
    if "db" not in g:
        db_path = get_database_path()
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row

        # Enable foreign-key constraints
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


# =========================================================
# DATABASE PATH
# =========================================================

def get_database_path():
    """
    Get database path from Flask configuration.
    Falls back to soc.db inside the project directory.
    """
    from flask import current_app

    database_path = current_app.config.get("DATABASE")

    if database_path:
        return database_path

    return os.path.join(
        current_app.root_path,
        "soc.db"
    )


# =========================================================
# CLOSE DATABASE
# =========================================================

def close_db(e=None):
    """
    Close the database connection at the end
    of the Flask request.
    """
    db = g.pop("db", None)

    if db is not None:
        db.close()


# =========================================================
# DATABASE MIGRATION HELPERS
# =========================================================

def add_column_if_missing(
    db,
    table_name,
    column_name,
    column_definition
):
    """
    Add a column to an existing table if that column
    does not already exist.

    This allows the project to update an existing soc.db
    without deleting user data.
    """

    columns = db.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    existing_columns = {
        column["name"]
        for column in columns
    }

    if column_name not in existing_columns:
        db.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
            """
        )


def migrate_database(db):
    """
    Apply safe schema migrations to an existing database.

    These migrations are intentionally non-destructive.
    Existing users, events, alerts, IOC records and tickets
    are preserved.
    """

    # =====================================================
    # ALERT THREAT INTELLIGENCE COLUMNS
    # =====================================================

    add_column_if_missing(
        db,
        "alerts",
        "threat_intel_match",
        "INTEGER NOT NULL DEFAULT 0"
    )

    add_column_if_missing(
        db,
        "alerts",
        "threat_intel_source",
        "TEXT"
    )

    add_column_if_missing(
        db,
        "alerts",
        "malware_family",
        "TEXT"
    )

    add_column_if_missing(
        db,
        "alerts",
        "mitre_attack",
        "TEXT"
    )

    # =====================================================
    # IOC EVENT COUNT
    # =====================================================

    add_column_if_missing(
        db,
        "iocs",
        "event_count",
        "INTEGER NOT NULL DEFAULT 1"
    )


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def init_db(app):
    """
    Create all required Mini SOC database tables.
    """

    # Register automatic DB cleanup
    app.teardown_appcontext(close_db)

    with app.app_context():

        db = get_db()

        # =================================================
        # USERS
        # =================================================

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        # =================================================
        # EVENTS
        # =================================================

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                destination_port INTEGER,
                status TEXT,
                message TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE
            )
            """
        )

        # =================================================
        # ALERTS
        # =================================================

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                source_ip TEXT,
                mitre_id TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN',

                -- Threat Intelligence enrichment
                threat_intel_match INTEGER NOT NULL DEFAULT 0,
                threat_intel_source TEXT,
                malware_family TEXT,
                mitre_attack TEXT,

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE
            )
            """
        )

        # =================================================
        # IOCs
        # =================================================

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                event_count INTEGER NOT NULL DEFAULT 1
            )
            """
        )

        # =================================================
        # IOC EVENTS
        # =================================================

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,

                FOREIGN KEY (
                    ioc_id
                )
                REFERENCES iocs(ioc_id)
                ON DELETE CASCADE,

                FOREIGN KEY (
                    event_id
                )
                REFERENCES events(id)
                ON DELETE CASCADE,

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE,

                UNIQUE (
                    ioc_id,
                    event_id
                )
            )
            """
        )

        # =================================================
        # SOC TICKETS
        # =================================================

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                alert_id INTEGER,
                event_id INTEGER,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                assignee TEXT DEFAULT 'SOC Analyst',
                source_ip TEXT,
                rule_name TEXT,
                mitre_id TEXT,
                resolution TEXT,

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE,

                FOREIGN KEY (
                    alert_id
                )
                REFERENCES alerts(id)
                ON DELETE SET NULL,

                FOREIGN KEY (
                    event_id
                )
                REFERENCES events(id)
                ON DELETE SET NULL
            )
            """
        )

        # =================================================
        # AUTHENTICATION FAILURES
        # =================================================

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                attempted_email TEXT,
                source_ip TEXT NOT NULL,
                attempted_at TEXT NOT NULL,

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE SET NULL
            )
            """
        )

        # =================================================
        # MIGRATE EXISTING DATABASE
        # =================================================

        migrate_database(db)

        # =================================================
        # AUTH FAILURE INDEXES
        # =================================================

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_auth_failures_ip_time
            ON auth_failures (
                source_ip,
                attempted_at
            )
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_auth_failures_email_time
            ON auth_failures (
                attempted_email,
                attempted_at
            )
            """
        )

        # =================================================
        # EVENT INDEXES
        # =================================================

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_events_user_id
            ON events(user_id)
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_events_timestamp
            ON events(timestamp)
            """
        )

        # =================================================
        # ALERT INDEXES
        # =================================================

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alerts_user_id
            ON alerts(user_id)
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alerts_created_at
            ON alerts(created_at)
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alerts_rule_ip
            ON alerts(
                rule_name,
                source_ip,
                created_at
            )
            """
        )

        # =================================================
        # THREAT INTEL INDEX
        # =================================================

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alerts_threat_intel
            ON alerts(
                threat_intel_match
            )
            """
        )

        # =================================================
        # TICKET INDEXES
        # =================================================

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_tickets_user_id
            ON tickets(user_id)
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_tickets_alert_id
            ON tickets(alert_id)
            """
        )

        # =================================================
        # IOC INDEXES
        # =================================================

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_iocs_type
            ON iocs(ioc_type)
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_ioc_events_user
            ON ioc_events(user_id)
            """
        )

        # =================================================
        # SAVE CHANGES
        # =================================================

        db.commit()
