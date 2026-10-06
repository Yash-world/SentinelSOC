# SentinelSOC — Full Technical Specification

## 1. Overview

SentinelSOC is a self-contained, single-server **Security Operations Center (SOC) simulator** built in **Flask + SQLite**. Each registered user gets their own isolated workspace: they submit security events (manually, or via the built-in live attack simulator), the system parses/enriches/correlates them, raises alerts, opens tickets, sends outbound notifications, and shows everything on a dashboard.

- **Type:** Web application (server-rendered pages + JSON API)
- **Language/Framework:** Python 3, Flask
- **Database:** SQLite (file: `soc.db`, auto-created)
- **Auth model:** Session-based, per-user data isolation (every query is scoped by `user_id`)
- **Architecture pattern:** Flask application factory + Blueprints (`auth_bp`, `main.bp`)

---

## 2. Tech Stack & Dependencies (`requirements.txt`)

| Package Version range Purpose |         |                          |
| ----------------------------- | ------- | ------------------------ |
| Flask                         | 3.x     | Web framework            |
| Flask-Limiter                 | 3.5–5.x | Rate limiting            |
| Flask-WTF                     | 1.2.x   | CSRF protection          |
| python-dotenv                 | 1.x     | Load `.env` config       |
| pytest                        | 8.x     | Testing                  |
| reportlab                     | 4.x     | PDF generation (tickets) |

Standard library also used: `sqlite3`, `hashlib`, `ipaddress`, `re`, `csv`, `io`, `json`, `secrets`, `random`, `smtplib`, `ssl`, `urllib.request`, `email.message`, `datetime`.

> No new third-party dependency was needed for alert notifications — `app/notifications.py` uses only the Python standard library (`urllib` for Slack webhooks, `smtplib`/`ssl` for email).

---

## 3. Application Configuration (`app/__init__.py`)

- **Factory function:** `create_app()`
- `SECRET_KEY` — **required** env var; app raises `RuntimeError` if missing
- `SESSION_COOKIE_HTTPONLY = True`
- `SESSION_COOKIE_SAMESITE = "Lax"`
- `SESSION_COOKIE_SECURE` — from `.env` (`SESSION_COOKIE_SECURE=true` for HTTPS deployments)
- `PERMANENT_SESSION_LIFETIME = 3600` seconds (1 hour)
- CSRF protection enabled globally via `Flask-WTF`
- `DATABASE` path = `<project_root>/soc.db`
- **Rate limiter defaults:** `200 requests/day`, `50 requests/hour` per client IP (`Flask-Limiter`, key = remote address)
- Blueprints registered: `auth_bp` (auth routes), `bp` (main app/API routes)
- `init_db(app)` runs on startup (creates tables + runs migrations)

### Environment variables (`.env.example`)

```
SECRET_KEY=replace-this-with-a-long-random-secret-key

FLASK_DEBUG=false
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# Alert notifications (all optional — leave blank to disable)
ALERT_NOTIFY_MIN_SEVERITY=HIGH
SLACK_WEBHOOK_URL=

ALERT_EMAIL_ENABLED=false
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
ALERT_EMAIL_FROM=
ALERT_EMAIL_TO=

```

All notification variables are optional. If `SLACK_WEBHOOK_URL` is blank and `ALERT_EMAIL_ENABLED` is not `true`, notifications are silently skipped and the app behaves exactly as it did before — nothing else changes.

---

## 4. Database Schema (`app/db.py`)

### `users`

| Column Type Notes |                          |                            |
| ----------------- | ------------------------ | -------------------------- |
| id                | INTEGER PK AUTOINCREMENT |                            |
| name              | TEXT NOT NULL            |                            |
| email             | TEXT NOT NULL UNIQUE     | lower-cased before storage |
| password_hash     | TEXT NOT NULL            | Werkzeug hash              |
| created_at        | TEXT NOT NULL            | ISO-8601 UTC               |

### `events`

| Column Type Notes |                                          |                                  |
| ----------------- | ---------------------------------------- | -------------------------------- |
| id                | INTEGER PK                               |                                  |
| user_id           | INTEGER FK → users(id) ON DELETE CASCADE |                                  |
| event_type        | TEXT NOT NULL                            | e.g. `failed_login`, `port_scan` |
| source_ip         | TEXT                                     | validated IPv4/IPv6              |
| username          | TEXT                                     | optional                         |
| destination_port  | INTEGER                                  | 1–65535                          |
| status            | TEXT                                     | optional                         |
| message           | TEXT                                     | normalized/raw log text          |
| timestamp         | TEXT NOT NULL                            | ISO-8601 UTC                     |

### `alerts`

| Column Type Notes   |                                          |                                        |
| ------------------- | ---------------------------------------- | -------------------------------------- |
| id                  | INTEGER PK                               |                                        |
| user_id             | INTEGER FK → users(id) ON DELETE CASCADE |                                        |
| created_at          | TEXT NOT NULL                            |                                        |
| severity            | TEXT NOT NULL                            | LOW / MEDIUM / HIGH / CRITICAL         |
| rule_name           | TEXT NOT NULL                            | e.g. `FAILED_LOGIN`, `BRUTE_FORCE`     |
| title               | TEXT NOT NULL                            |                                        |
| description         | TEXT                                     |                                        |
| source_ip           | TEXT                                     |                                        |
| mitre_id            | TEXT                                     | e.g. `T1110`                           |
| status              | TEXT NOT NULL DEFAULT `OPEN`             | OPEN / IN_PROGRESS / RESOLVED / CLOSED |
| threat_intel_match  | INTEGER DEFAULT 0                        | boolean flag (migration-added)         |
| threat_intel_source | TEXT                                     | JSON array (migration-added)           |
| malware_family      | TEXT                                     | JSON array (migration-added)           |
| mitre_attack        | TEXT                                     | JSON array (migration-added)           |

### `iocs` (Indicators of Compromise)

| Column Type Notes      |                       |                                                 |
| ---------------------- | --------------------- | ----------------------------------------------- |
| ioc_id                 | INTEGER PK            |                                                 |
| ioc_type               | TEXT NOT NULL         | ip / domain / url / email / md5 / sha1 / sha256 |
| value                  | TEXT NOT NULL UNIQUE  | normalized (de-fanged forms merged)             |
| first_seen / last_seen | TEXT NOT NULL         |                                                 |
| status                 | TEXT DEFAULT `ACTIVE` |                                                 |
| event_count            | INTEGER DEFAULT 1     | number of linked events (migration-added)       |

### `ioc_events` (junction table)

Links `iocs` ↔ `events` ↔ `users`, with `UNIQUE(ioc_id, event_id)` and cascading deletes.

### `tickets`

| Column Type Notes                          |                                          |                                                             |
| ------------------------------------------ | ---------------------------------------- | ----------------------------------------------------------- |
| id                                         | INTEGER PK                               |                                                             |
| ticket_id                                  | TEXT UNIQUE                              | format `SOC-YYYYMMDD-00001` (daily counter)                 |
| user_id                                    | INTEGER FK                               |                                                             |
| alert_id                                   | INTEGER FK → alerts (ON DELETE SET NULL) |                                                             |
| event_id                                   | INTEGER FK → events (ON DELETE SET NULL) |                                                             |
| created_at                                 | TEXT NOT NULL                            |                                                             |
| title, description                         | TEXT                                     |                                                             |
| severity                                   | TEXT NOT NULL                            |                                                             |
| priority                                   | TEXT NOT NULL                            | P1 (CRITICAL) / P2 (HIGH) / P3 (MEDIUM) / P4 (LOW, default) |
| status                                     | TEXT DEFAULT `OPEN`                      |                                                             |
| assignee                                   | TEXT DEFAULT `SOC Analyst`               |                                                             |
| source_ip, rule_name, mitre_id, resolution | TEXT                                     |                                                             |

### `auth_failures`

Tracks every failed login attempt (`user_id` nullable for unknown emails), used for brute-force detection.
Indexes: `(source_ip, attempted_at)`, `(attempted_email, attempted_at)`.

### Other indexes

`events(user_id)`, `events(timestamp)`, `alerts(user_id)`, `alerts(created_at)`, `alerts(rule_name, source_ip, created_at)`, `alerts(threat_intel_match)`, `tickets(user_id)`, `tickets(alert_id)`, `iocs(ioc_type)`, `ioc_events(user_id)`.

### Migrations

`migrate_database()` non-destructively adds new columns (`threat_intel_match`, `threat_intel_source`, `malware_family`, `mitre_attack` on `alerts`; `event_count` on `iocs`) to existing databases without deleting data.

---

## 5. Authentication (`app/auth.py`)

- **Session invalidation on restart:** a random `SERVER_INSTANCE_ID` is generated at process start; any session tagged with an older instance ID is cleared (`reset_stale_session`).
- **Register** (`GET/POST /register`):
  - Fields: name, email, password, confirm_password
  - Validations: name required; email required; password required, **min 8 characters**; password == confirm_password; email must not already exist
  - Password hashed with Werkzeug (`generate_password_hash`)
  - Does **not** auto-login — flow is Register → Login → Input → Dashboard
- **Login** (`GET/POST /login`):
  - Looks up user by (lower-cased) email, verifies password hash
  - On failure (unknown email OR wrong password): records a row in `auth_failures` and checks brute-force threshold
  - On success: `session.clear()`, then sets `user_id`, `email`, `name`, `server_instance`
- **Brute-force detection (auth-layer):**
  - Threshold: **5 failed attempts** from the same `source_ip` within **5 minutes**
  - On threshold breach: creates a `HIGH` severity alert, `rule_name = BRUTE_FORCE_LOGIN`, `mitre_id = T1110`
  - Deduplicated — won't create a second alert for the same IP within the same 5-minute window
- **Logout** (`GET /logout`): clears session, flashes message, redirects to login.

---

## 6. Log Analyzer (`app/log_analyzer.py`)

Normalizes free-text log lines into structured event fields.

- **Event type normalization map**, e.g.:
  - "failed login" / "login failed" / "invalid password" → `failed_login`
  - "authentication failure/failed" / "auth failure" → `authentication_failure`
  - "port scan" / "network scan" / "nmap scan" → `port_scan` / `network_scan`
  - "malware detected" → `malware_detected`; "virus/trojan/ransomware detected" → `virus`/`trojan`/`ransomware`
  - "suspicious/unusual login", "login anomaly" → `suspicious_login` / `unusual_login` / `login_anomaly`
- **Extraction regexes:**
  - IP: `\b(?:\d{1,3}\.){3}\d{1,3}\b` (validated with `ipaddress`)
  - Port: `port\s*[:=]?\s*(\d{1,5})` or `:(\d{1,5})`
  - Username: `(?:user|username|account|for)\s*[=:]?\s*([A-Za-z0-9_.@-]+)`

## 7. IOC Tracker (`app/ioc_tracker.py`)

Extracts Indicators of Compromise from event text:

- **IPs** — IPv4 regex + validity check
- **Domains** — generic domain regex
- **URLs** — `https?://...`
- **Emails** — standard email regex
- **File hashes** — MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
- IOCs are de-duplicated, linked to the originating event/user (`ioc_events`), and each IOC's `event_count` is kept up to date.

## 8. Threat Intelligence (`app/threat_intel.py`, `data/threat_intel.json`)

- Local static feed (`threat_intelligence` metadata + `indicators` array, 12 sample indicators). Sample fields per indicator: `id`, `type`, `value`, `indicator_type`, `category`, `threat_type`, `malware_family`, `threat_actor`, `severity`, `confidence`, `risk_score`, `reputation`, `country`, `asn`, `first_seen`, `last_seen`, `status`, `mitre_attack[]`, `tags[]`, `description`.
- **`normalize_ioc_value()`** — treats de-fanged IOCs as equivalent to real ones (`[.]`, `(.)`, `[dot]` → `.`)
- **`enrich_iocs(iocs)`** — matches extracted IOCs against the feed by normalized value
- **`boost_severity(current_severity, matches)`** — raises an alert's severity if a matched threat-intel indicator has a higher severity rank (`LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4`)

## 9. Detection Engine (`app/detection.py`)

Runs **8 independent per-event rules**, any number of which can fire on a single event:

| Rule (`rule_name`) Trigger keywords / event_type Severity MITRE ATT&CK |                                                                                     |          |       |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | -------- | ----- |
| `FAILED_LOGIN`                                                         | `event_type == failed_login` or "failed login" in message                           | HIGH     | T1110 |
| `BRUTE_FORCE`                                                          | `event_type == brute_force` or "brute force" in message                             | HIGH     | T1110 |
| `NETWORK_PORT_SCAN`                                                    | "scan" in event_type, or "port scan"/"network scan" in message                      | HIGH     | T1046 |
| `MALWARE_DETECTED`                                                     | "malware"/"trojan"/"ransomware"/"virus"/"malicious" in message                      | CRITICAL | T1204 |
| `UNAUTHORIZED_ACCESS`                                                  | "unauthorized" in message/status, or "intrusion" in message                         | CRITICAL | T1078 |
| `EXPLOIT_ACTIVITY`                                                     | "exploit" in message/event_type                                                     | CRITICAL | T1190 |
| `PHISHING_ACTIVITY`                                                    | "phishing" in message                                                               | HIGH     | T1566 |
| `SUSPICIOUS_LOGIN`                                                     | `suspicious_login` in event_type, or "suspicious login"/"multiple login" in message | MEDIUM   | T1078 |

**Correlation rules** (run against the user's last 100 events):

- **`detect_brute_force`** — 5+ `failed_login` events from the same source IP within a rolling 5-minute window → HIGH alert (`BRUTE_FORCE`)
- **`detect_port_scan`** — 5+ unique destination ports from the same source IP (event_type `port_scan`) → HIGH alert (`PORT_SCAN_PATTERN`, T1046)

**Pipeline per submitted event** (`process_event`, orchestrated by `app/routes.py::_ingest_event`):

1. Run all 8 event-level rules → 0..N alerts
2. Pull recent event history (last 100 events for that user)
3. Run brute-force correlation
4. Run port-scan correlation
5. De-duplicate alerts with the same `(rule_name, source_ip)` in this batch
6. If none fired → return `detected: False`
7. Enrich each alert with threat-intel matches (may bump severity, attach `malware_family`, `mitre_attack`, `threat_intel_source`)
8. **Deduplication against DB history:** a SHA-256 fingerprint is built per alert:
   - Correlation alerts (`BRUTE_FORCE`, `PORT_SCAN_PATTERN`): fingerprint = `user + rule + source_ip`
   - Other alerts: fingerprint = `user + rule + source_ip + event_type + username + destination_port + message`
   - If a matching alert already exists within the last **5 minutes**, the alert is not re-inserted — the existing alert ID is reused
9. New (non-duplicate) alerts each automatically create a SOC ticket
10. **Outbound notifications:** every newly created (non-duplicate) alert is passed to `notify_alert()` (see §10 below) — deduplicated repeats of an already-open alert are never re-notified
11. Returns both the legacy single-alert shape (`alert`, `alert_id`, `ticket`) and the new multi-alert shape (`alerts[]`, `alert_ids[]`, `tickets[]`)



## 10. Live Attack Simulator (`app/routes.py::simulate_event`) — *new*

Powers the "Simulate live attack traffic" control on the Input page so the project can be demoed without a real log source.

- **`POST /api/events/simulate`** — generates one randomized, realistic event (`_generate_simulated_event`) from a pool of six templates (`failed_login`, `port_scan`, `malware`, `suspicious_login`, `phishing`, and a benign `network_connection` event) with a randomized public-looking source IP, username, and destination port, then feeds it through the **exact same** ingestion pipeline as a manually submitted log (`_ingest_event` — shared by both `/api/events` and `/api/events/simulate`).
- Because it reuses `_ingest_event`, every simulated event still goes through log analysis, IOC extraction, threat-intel enrichment, detection, ticket creation, and notifications — it is not a separate, simplified code path.
- Intended to be called repeatedly (e.g. every 2–3 seconds from the browser) to stream a live-looking feed of alerts, IOCs, and tickets onto the dashboard for demos.

## 11. Ticketing (`app/ticketing.py`)

- **Ticket ID format:** `SOC-YYYYMMDD-00001` — a daily auto-incrementing counter per date
- **Priority mapping from severity:** CRITICAL→P1, HIGH→P2, MEDIUM→P3, LOW→P4 (default P4 if unknown)
- **Default assignee:** `SOC Analyst`
- **Ticket statuses:** `OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`
- **PDF export** (`generate_ticket_pdf`) — built with ReportLab (`SimpleDocTemplate`, A4 page), includes a header (`SOC INCIDENT TICKET — <ticket_id>`), a details table, and safely escapes/handles `NULL` fields (renders as `-`)

## 12. Web Pages / Templates (`app/templates/`)

| Route Template Auth required |                  |                                                     |
| ---------------------------- | ---------------- | --------------------------------------------------- |
| `GET /`                      | —                | redirects to `/login`                               |
| `GET/POST /register`         | `register.html`  | No                                                  |
| `GET/POST /login`            | `login.html`     | No                                                  |
| `GET /logout`                | —                | Yes (session cleared)                               |
| `GET /input`                 | `input.html`     | Yes — event submission form + live attack simulator |
| `GET /dashboard`             | `dashboard.html` | Yes — stats, alerts, IOCs, tickets                  |

## 13. REST API (`app/routes.py`)

All endpoints below (except pages already listed) require an authenticated session (`login_required()` → redirect to login if missing) and are scoped to `user_id = session["user_id"]`.

### Summary

- `GET /api/summary` → `{total, critical, high, medium, open}` alert counts for the current user

### Events

- `GET /api/events` — filters: `event_type`, `source_ip`, `status`, `username`; supports pagination (see below)
- `POST /api/events` — body: `event_type` (required), `source_ip` (required, validated IP), `username`, `destination_port` (1–65535), `raw_log`/`message`. Runs the full pipeline: log analysis → IOC extraction → threat-intel enrichment → detection → ticket creation → notifications. Returns `201` with `event_id`, `detected`, `alert_id`, `alert`, `ticket`, `alert_ids[]`, `alerts[]`, `tickets[]`, `ioc_count`, `iocs[]`, `threat_intel_matches[]`, `threat_intel_match_count`.
- `POST /api/events/simulate` — *(new)* same request/response shape as `POST /api/events`, but the event body is auto-generated server-side instead of supplied by the client. Used by the Input page's live attack simulator.

### Alerts

- `GET /api/alerts` — filters: `severity`, `status`, `rule_name`, `source_ip`; paginated
- `GET /api/alerts/<id>` — single alert (404 if not found / not owned by user)

### IOCs

- `GET /api/iocs` — filters: `ioc_type`, `status`, `value`; paginated; each item enriched with `id`, `type`, `created_at`, `source: "Local IOC Tracker"`
- `GET /api/iocs/summary` — counts by type: `{total, ip, domain, url, email, md5, sha1, sha256}`

### Tickets

- `GET /api/tickets` — filters: `status`, `severity`, `priority`, `assignee`; paginated
- `GET /api/tickets/<id>` — single ticket
- `PATCH /api/tickets/<id>` — update `status`; must be one of `OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED` (400 otherwise)
- `GET /api/tickets/<id>/pdf` — download ticket as PDF (`Content-Disposition: attachment`)

### Reporting

- `GET /api/report.csv` — download all of the user's alerts (id, severity, status, rule_name, source_ip, created_at) as CSV

### Pagination convention (used by `/api/alerts`, `/api/events`, `/api/iocs`, `/api/tickets`)

- Backward-compatible: with **no** `page`/`per_page`/filter query params → returns a plain JSON array (legacy behavior)
- With `page`, `per_page`, or any filter param present → returns:

```
{
  "items": [...],
  "pagination": {
    "page": 1,
    "per_page": 25,
    "total": 42,
    "pages": 2,
    "has_next": true,
    "has_previous": false
  }
}

```

- `page` defaults to 1 (min 1); `per_page` defaults to 25 (clamped 1–100)

---

## 14. Security Measures

- Session cookies: `HttpOnly`, `SameSite=Lax`, optional `Secure` flag for HTTPS
- CSRF protection on all forms (Flask-WTF)
- Passwords hashed (never stored in plaintext) via Werkzeug
- Server-restart session invalidation (prevents stale/replayed sessions across restarts)
- Rate limiting: 200 requests/day, 50/hour per IP by default
- Brute-force detection at both the **auth layer** (`auth.py`) and the **detection engine** (`detection.py`, via correlation on `failed_login` events)
- Strict input validation: IP format (`ipaddress` module), port range (1–65535), required fields
- All data access scoped per `user_id` — no cross-user data leakage
- Outbound notification failures (unreachable webhook, bad SMTP credentials, network errors) are caught and swallowed — they can never crash or block event ingestion
- `.env` and `soc.db`/`*.sqlite*` excluded from git via `.gitignore`

---

## 15. Testing (`tests/`)

- `test_detection.py` — detection rule/engine tests
- `test_iocs_tracker.py` — IOC extraction tests
- `test_log_analyzer.py` — log normalization tests
- Run via `pytest` (config in `pytest.ini`)

---

## 16. Getting Started

```
# 1. Clone and enter the project
git clone <your-repo-url>
cd sentinelsoc

# 2. Create a virtual environment and install dependencies
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste output into SECRET_KEY in .env

# 4. (Optional) enable Slack and/or email alert notifications in .env

# 5. Run
python run.py

```

Then open `http://127.0.0.1:5000`, register an account, log in, and either submit a log manually on the Input page or click "Simulate live attack traffic" to see the full pipeline run end to end.

---

## 17. Screenshots

### 17.1 Register Page

<img width="1920" height="1080" alt="Screenshot (335)" src="https://github.com/user-attachments/assets/2ac73541-4dcb-46e1-9a06-cc6e57ce705e" />


### 17.2 Login Page

<img width="1920" height="1080" alt="Screenshot (334)" src="https://github.com/user-attachments/assets/c5708d59-5e5b-4864-b533-95c40262a824" />


### 17.3 Input / Event Submission Page

<img width="1920" height="1080" alt="Screenshot (337)" src="https://github.com/user-attachments/assets/2ace16fc-a61b-4bcd-8875-08a7d37aacb0" />


### 17.4 Dashboard
<img width="1920" height="712" alt="Screenshot (338)" src="https://github.com/user-attachments/assets/a7e94ee4-7f4f-4c8f-ac7f-d886c2d3bb38" />
<img width="1920" height="858" alt="Screenshot (339)" src="https://github.com/user-attachments/assets/9ac02fb3-e284-4dd0-b306-bfc577dac7e7" />
<img width="1920" height="972" alt="Screenshot (340)" src="https://github.com/user-attachments/assets/18b7dbce-df7b-4de7-9f2e-37170e72300e" />





### 17.5 PDF Ticket
<img width="984" height="1080" alt="Screenshot (343)" src="https://github.com/user-attachments/assets/bd3bcd86-d8bd-4de9-ad7f-8a50d777fa66" />



## 18. Project File Map

```
sentinelsoc/
├── app/
│   ├── __init__.py       (136 lines)  – app factory, config, extensions
│   ├── auth.py            (629 lines) – register/login/logout, brute-force detection
│   ├── db.py              (508 lines) – schema, migrations, connection handling
│   ├── detection.py      (1244 lines) – 8 detection rules + correlation + dedup + tickets + notify hook
│   ├── ioc_tracker.py     (345 lines) – IOC regex extraction
│   ├── log_analyzer.py    (449 lines) – raw log normalization
│   ├── notifications.py   (241 lines) – Slack + email alert notifications *(new)*
│   ├── routes.py         (1729 lines) – all page + REST API routes + live attack simulator
│   ├── threat_intel.py    (469 lines) – threat feed matching, severity boosting
│   ├── ticketing.py       (625 lines) – ticket creation + PDF export
│   └── templates/          – login.html, register.html, input.html, dashboard.html
├── data/threat_intel.json  – local simulated threat intel feed (12 indicators)
├── tests/                  – pytest suite
├── run.py                  – entry point (host/port/debug from env)
├── requirements.txt
├── pytest.ini
├── .env.example
└── .gitignore

```
