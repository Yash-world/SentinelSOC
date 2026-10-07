# SentinelSOC — Technical Specification

## 1. Overview

SentinelSOC is a self-contained, single-server **Security Operations Center (SOC) simulator** built with **Flask + SQLite**. Each registered user gets an isolated workspace: they submit security events manually, and the system parses, enriches and correlates them, raises alerts, opens tickets, and shows everything on a dashboard.

* **Type:** Web application (server-rendered pages + JSON API)
* **Language/Framework:** Python 3, Flask
* **Database:** SQLite (file: `soc.db`, auto-created)
* **Auth model:** Session-based, per-user data isolation (every query is scoped by `user_id`)
* **Architecture pattern:** Flask application factory + Blueprints (`auth_bp`, `main.bp`)

---

## 2. Tech Stack & Dependencies (`requirements.txt`)

| Package       | Version range | Purpose                  |
| ------------- | ------------- | ------------------------ |
| Flask         | 3.x           | Web framework            |
| Flask-Limiter | 3.5 – 4.x     | Rate limiting            |
| Flask-WTF     | 1.2.x         | CSRF protection          |
| python-dotenv | 1.x           | Load `.env` config       |
| pytest        | 8.x           | Testing                  |
| reportlab     | 4.x           | PDF generation (tickets) |
| gunicorn      | 23.x          | Production WSGI server   |

Standard library also used: `sqlite3`, `hashlib`, `ipaddress`, `re`, `csv`, `io`, `json`, `secrets`, `datetime`.

---

## 3. Application Configuration (`app/__init__.py`)

* **Factory function:** `create_app()`
* `SECRET_KEY` — **required** env var; the app raises `RuntimeError` if it is missing
* `SESSION_COOKIE_HTTPONLY = True`
* `SESSION_COOKIE_SAMESITE = "Lax"`
* `SESSION_COOKIE_SECURE` — read from env (`SESSION_COOKIE_SECURE=true` for HTTPS deployments, default `false`)
* `PERMANENT_SESSION_LIFETIME = 3600` seconds (1 hour)
* CSRF protection enabled globally via Flask-WTF
* `DATABASE` path = `<project_root>/soc.db`
* **Rate limiter defaults:** `200 per day`, `50 per hour` per client IP (Flask-Limiter, key = remote address)
* Blueprints registered: `auth_bp` (auth routes), `bp` (pages + API routes)
* `init_db(app)` runs on startup (creates tables, indexes and runs migrations)

### Environment variables

| Variable                | Default / example                         | Description                                   |
| ----------------------- | ----------------------------------------- | --------------------------------------------- |
| `SECRET_KEY`            | *(required)*                              | Flask secret key                              |
| `FLASK_DEBUG`           | `false`                                   | Enables Flask debug mode when `true`          |
| `FLASK_HOST`            | `0.0.0.0`                                 | Host to bind to                               |
| `PORT`                  | `5000`                                    | Port to listen on                             |
| `SESSION_COOKIE_SECURE` | `false`                                   | Set `true` when serving over HTTPS            |

`.env.example` ships with:

```
SECRET_KEY=replace-this-with-a-long-random-secret-key
FLASK_DEBUG=false
FLASK_HOST=0.0.0.0
```

`PORT` and `SESSION_COOKIE_SECURE` are optional and can be added to your `.env`.

---

## 4. Database Schema (`app/db.py`)

### `users`

| Column        | Type                     | Notes                      |
| ------------- | ------------------------ | -------------------------- |
| id            | INTEGER PK AUTOINCREMENT |                            |
| name          | TEXT NOT NULL            |                            |
| email         | TEXT NOT NULL UNIQUE     | lower-cased before storage |
| password_hash | TEXT NOT NULL            | Werkzeug hash              |
| created_at    | TEXT NOT NULL            | ISO-8601 UTC               |

### `events`

| Column           | Type                                     | Notes                            |
| ---------------- | ---------------------------------------- | -------------------------------- |
| id               | INTEGER PK                               |                                  |
| user_id          | INTEGER NOT NULL → users(id) CASCADE     |                                  |
| event_type       | TEXT NOT NULL                            | e.g. `failed_login`, `port_scan` |
| source_ip        | TEXT                                     | validated IPv4/IPv6              |
| username         | TEXT                                     | optional                         |
| destination_port | INTEGER                                  | 1–65535                          |
| status           | TEXT                                     | optional                         |
| message          | TEXT                                     | normalized/raw log text          |
| timestamp        | TEXT NOT NULL                            | ISO-8601 UTC                     |

### `alerts`

| Column              | Type                          | Notes                                  |
| ------------------- | ----------------------------- | -------------------------------------- |
| id                  | INTEGER PK                    |                                        |
| user_id             | INTEGER NOT NULL → users(id)  |                                        |
| created_at          | TEXT NOT NULL                 |                                        |
| severity            | TEXT NOT NULL                 | LOW / MEDIUM / HIGH / CRITICAL         |
| rule_name           | TEXT NOT NULL                 | e.g. `FAILED_LOGIN`, `BRUTE_FORCE`     |
| title               | TEXT NOT NULL                 |                                        |
| description         | TEXT                          |                                        |
| source_ip           | TEXT                          |                                        |
| mitre_id            | TEXT                          | e.g. `T1110`                           |
| status              | TEXT NOT NULL DEFAULT `OPEN`  | OPEN / IN_PROGRESS / RESOLVED / CLOSED |
| threat_intel_match  | INTEGER NOT NULL DEFAULT 0    | boolean flag (migration-added)         |
| threat_intel_source | TEXT                          | JSON array (migration-added)           |
| malware_family      | TEXT                          | JSON array (migration-added)           |
| mitre_attack        | TEXT                          | JSON array (migration-added)           |

### `iocs` (Indicators of Compromise)

| Column                 | Type                          | Notes                                           |
| ---------------------- | ----------------------------- | ----------------------------------------------- |
| ioc_id                 | INTEGER PK AUTOINCREMENT      |                                                 |
| ioc_type               | TEXT NOT NULL                 | ip / domain / url / email / md5 / sha1 / sha256 |
| value                  | TEXT NOT NULL UNIQUE          | normalized (de-fanged forms merged)             |
| first_seen / last_seen | TEXT NOT NULL                 |                                                 |
| status                 | TEXT NOT NULL DEFAULT `ACTIVE`|                                                 |
| event_count            | INTEGER NOT NULL DEFAULT 1    | number of linked events (migration-added)       |

### `ioc_events` (junction table)

Links `iocs` ↔ `events` ↔ `users` (`ioc_id`, `event_id`, `user_id`, `created_at`), with `UNIQUE(ioc_id, event_id)` and cascading deletes.

### `tickets`

| Column                                     | Type                                     | Notes                                                       |
| ------------------------------------------ | ---------------------------------------- | ----------------------------------------------------------- |
| id                                         | INTEGER PK                               |                                                             |
| ticket_id                                  | TEXT NOT NULL UNIQUE                     | format `SOC-YYYYMMDD-00001` (daily counter)                 |
| user_id                                    | INTEGER NOT NULL                         |                                                             |
| alert_id                                   | INTEGER → alerts (ON DELETE SET NULL)    |                                                             |
| event_id                                   | INTEGER → events (ON DELETE SET NULL)    |                                                             |
| created_at                                 | TEXT NOT NULL                            |                                                             |
| title                                      | TEXT NOT NULL                            |                                                             |
| description                                | TEXT                                     |                                                             |
| severity                                   | TEXT NOT NULL                            |                                                             |
| priority                                   | TEXT NOT NULL                            | P1 (CRITICAL) / P2 (HIGH) / P3 (MEDIUM) / P4 (LOW, default) |
| status                                     | TEXT NOT NULL DEFAULT `OPEN`             |                                                             |
| assignee                                   | TEXT DEFAULT `SOC Analyst`               |                                                             |
| source_ip, rule_name, mitre_id, resolution | TEXT                                     |                                                             |

### `auth_failures`

Tracks every failed login attempt (`user_id` is nullable for unknown emails; also stores `attempted_email`, `source_ip`, `attempted_at`). Used for brute-force detection.

### Indexes

`auth_failures(source_ip, attempted_at)`, `auth_failures(attempted_email, attempted_at)`, `events(user_id)`, `events(timestamp)`, `alerts(user_id)`, `alerts(created_at)`, `alerts(rule_name, source_ip, created_at)`, `alerts(threat_intel_match)`, `tickets(user_id)`, `tickets(alert_id)`, `iocs(ioc_type)`, `ioc_events(user_id)`.

### Migrations

`migrate_database()` non-destructively adds new columns (`threat_intel_match`, `threat_intel_source`, `malware_family`, `mitre_attack` on `alerts`; `event_count` on `iocs`) to existing databases without deleting data.

---

## 5. Authentication (`app/auth.py`)

* **Session invalidation on restart:** a random `SERVER_INSTANCE_ID` is generated at process start; any session tagged with an older instance ID is cleared (`reset_stale_session`).
* **Register** (`GET/POST /register`):
  * Fields: name, email, password, confirm_password
  * Validations: name required; email required; password required with **minimum 8 characters**; password must match confirm_password; email must not already exist
  * Password hashed with Werkzeug (`generate_password_hash`)
  * Does **not** auto-login — flow is Register → Login → Input → Dashboard
* **Login** (`GET/POST /login`):
  * Looks up the user by (lower-cased) email and verifies the password hash
  * On failure (unknown email or wrong password): records a row in `auth_failures` and checks the brute-force threshold
  * On success: `session.clear()`, then sets `user_id`, `email`, `name`, `server_instance`
* **Brute-force detection (auth layer):**
  * Threshold: **5 failed attempts** from the same `source_ip` within **5 minutes**
  * On breach: creates a `HIGH` alert with `rule_name = BRUTE_FORCE_LOGIN`, `mitre_id = T1110`
  * Deduplicated — no second alert for the same IP within the same 5-minute window
* **Logout** (`GET /logout`): clears the session, flashes a message, redirects to login.

---

## 6. Log Analyzer (`app/log_analyzer.py`)

Normalizes free-text log lines into structured event fields.

* **Event type normalization map:**

  | Phrase in log                                                | Normalized `event_type`  |
  | ------------------------------------------------------------ | ------------------------ |
  | "failed login", "login failed", "invalid password"           | `failed_login`           |
  | "authentication failure", "authentication failed", "auth failure" | `authentication_failure` |
  | "port scan", "port scanning", "nmap scan"                    | `port_scan`              |
  | "network scan"                                               | `network_scan`           |
  | "malware detected"                                           | `malware_detected`       |
  | "virus detected" / "trojan detected" / "ransomware detected" | `virus` / `trojan` / `ransomware` |
  | "suspicious login"                                           | `suspicious_login`       |
  | "unusual login"                                              | `unusual_login`          |
  | "login anomaly"                                              | `login_anomaly`          |

* **Extraction regexes:**
  * IP: `\b(?:\d{1,3}\.){3}\d{1,3}\b` (validated with `ipaddress`)
  * Port: `(?:port\s*[:=]?\s*|:)(\d{1,5})\b` (case-insensitive)
  * Username: `(?:user|username|account|for)\s*[=:]?\s*([A-Za-z0-9_.@-]+)` (case-insensitive)

---

## 7. IOC Tracker (`app/ioc_tracker.py`)

Extracts Indicators of Compromise from event text:

* **IPs** — IPv4 regex + validity check
* **Domains** — generic domain regex
* **URLs** — `http(s)://...`
* **Emails** — standard email regex
* **File hashes** — MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)

IOCs are de-duplicated, linked to the originating event/user (`ioc_events`), and each IOC's `event_count` is kept up to date.

---

## 8. Threat Intelligence (`app/threat_intel.py`, `data/threat_intel.json`)

* Local static feed: a `threat_intelligence` metadata block plus an `indicators` array of **12 sample indicators**. Fields per indicator: `id`, `type`, `value`, `indicator_type`, `category`, `threat_type`, `malware_family`, `threat_actor`, `severity`, `confidence`, `risk_score`, `reputation`, `country`, `asn`, `first_seen`, `last_seen`, `status`, `mitre_attack[]`, `tags[]`, `description`.
* **`normalize_ioc_value()`** — treats de-fanged IOCs as equivalent to real ones (`[.]`, `(.)`, `[dot]` → `.`)
* **`enrich_iocs(iocs)`** — matches extracted IOCs against the feed by normalized value
* **`boost_severity(current_severity, matches)`** — raises an alert's severity if a matched indicator has a higher severity rank (`LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4`)
* Helpers `get_sources()`, `get_malware_families()` and `get_mitre_attack()` collect the matched metadata that is attached to alerts.

---

## 9. Detection Engine (`app/detection.py`)

Runs **8 event-level rules**; any number of them can fire on a single event:

| Rule (`rule_name`)    | Trigger keywords / event_type                                                       | Severity | MITRE ATT&CK |
| --------------------- | ----------------------------------------------------------------------------------- | -------- | ------------ |
| `FAILED_LOGIN`        | `event_type == failed_login` or "failed login" in message                           | HIGH     | T1110        |
| `BRUTE_FORCE`         | `event_type == brute_force` or "brute force" in message                             | HIGH     | T1110        |
| `NETWORK_PORT_SCAN`   | "scan" in event_type, or "port scan" / "network scan" in message                    | HIGH     | T1046        |
| `MALWARE_DETECTED`    | malware-related keywords (malware, trojan, ransomware, virus, malicious) in message | CRITICAL | T1204        |
| `UNAUTHORIZED_ACCESS` | "unauthorized" in message/status, or "intrusion" in message                         | CRITICAL | T1078        |
| `EXPLOIT_ACTIVITY`    | "exploit" in message/event_type                                                     | CRITICAL | T1190        |
| `PHISHING_ACTIVITY`   | "phishing" in message                                                               | HIGH     | T1566        |
| `SUSPICIOUS_LOGIN`    | `suspicious_login` in event_type, or "suspicious login" / "multiple login" in message | MEDIUM | T1078        |

**Correlation rules** (run against the user's recent events):

* **`detect_brute_force`** — 5+ `failed_login` events from the same source IP within a rolling 5-minute window → HIGH alert (`BRUTE_FORCE`, T1110)
* **`detect_port_scan`** — 5+ unique destination ports from the same source IP → HIGH alert (`PORT_SCAN_PATTERN`, T1046)

**Pipeline per submitted event** (`POST /api/events` in `app/routes.py`, using `process_event` from `app/detection.py`):

1. Parse the submitted fields and normalize them with the log analyzer
2. Extract IOCs and enrich them with threat intelligence
3. Run all 8 event-level rules → 0..N alerts
4. Pull the user's recent event history and run the brute-force and port-scan correlations
5. De-duplicate alerts with the same `(rule_name, source_ip)` within the batch
6. If nothing fired → return `detected: False`
7. Enrich each alert with threat-intel matches (may raise severity, attach `malware_family`, `mitre_attack`, `threat_intel_source`)
8. **Deduplication against DB history:** a SHA-256 fingerprint is built per alert:
   * Correlation alerts (`BRUTE_FORCE`, `PORT_SCAN_PATTERN`): `user + rule + source_ip`
   * Other alerts: `user + rule + source_ip + event_type + username + destination_port + message`
   * If a matching alert already exists within the last **5 minutes**, it is not re-inserted and the existing alert ID is reused
9. Each new (non-duplicate) alert automatically creates a SOC ticket
10. The response contains both the legacy single-alert shape (`alert`, `alert_id`, `ticket`) and the multi-alert shape (`alerts[]`, `alert_ids[]`, `tickets[]`)

---

## 10. Ticketing (`app/ticketing.py`)

* **Ticket ID format:** `SOC-YYYYMMDD-00001` — a daily auto-incrementing counter per date
* **Priority mapping from severity:** CRITICAL → P1, HIGH → P2, MEDIUM → P3, LOW → P4 (default P4 if unknown)
* **Default assignee:** `SOC Analyst`
* **Ticket statuses:** `OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`
* **PDF export** (`generate_ticket_pdf`) — built with ReportLab (`SimpleDocTemplate`, A4 page), includes a header (`SOC INCIDENT TICKET — <ticket_id>`) and a details table; values are safely escaped and `NULL` fields render as `-`

---

## 11. Web Pages / Templates (`templates/`)

| Route                | Template         | Auth required / notes                  |
| -------------------- | ---------------- | -------------------------------------- |
| `GET /`              | —                | Redirects to `/login`                  |
| `GET/POST /register` | `register.html`  | No                                     |
| `GET/POST /login`    | `login.html`     | No                                     |
| `GET /logout`        | —                | Clears the session, redirects to login |
| `GET /input`         | `input.html`     | Yes — event submission form            |
| `GET /dashboard`     | `dashboard.html` | Yes — stats, alerts, IOCs, tickets     |

---

## 12. REST API (`app/routes.py`)

All API endpoints require an authenticated session (`login_required()` → redirect to login if missing) and are scoped to `user_id = session["user_id"]`.

### Summary

* `GET /api/summary` → `{total, critical, high, medium, open}` alert counts for the current user

### Events

* `GET /api/events` — filters: `event_type`, `source_ip`, `status`, `username`; supports pagination
* `POST /api/events` — body: `event_type` (required), `source_ip` (required, validated IP), `username`, `destination_port` (1–65535), `raw_log` / `message`. Runs the full pipeline: log analysis → IOC extraction → threat-intel enrichment → detection → ticket creation. Returns `201` with `event_id`, `detected`, `alert_id`, `alert`, `ticket`, `alert_ids[]`, `alerts[]`, `tickets[]`, `ioc_count`, `iocs[]`, `threat_intel_matches[]`, `threat_intel_match_count`.

### Alerts

* `GET /api/alerts` — filters: `severity`, `status`, `rule_name`, `source_ip`; paginated
* `GET /api/alerts/<id>` — single alert (404 if not found / not owned by the user)

### IOCs

* `GET /api/iocs` — filters: `ioc_type`, `status`, `value`; paginated
* `GET /api/iocs/summary` — counts by type: `{total, ip, domain, url, email, md5, sha1, sha256}`

### Tickets

* `GET /api/tickets` — filters: `status`, `severity`, `priority`, `assignee`; paginated
* `GET /api/tickets/<id>` — single ticket
* `PATCH /api/tickets/<id>` — update `status`; must be one of `OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED` (400 otherwise)
* `GET /api/tickets/<id>/pdf` — download the ticket as a PDF (`Content-Disposition: attachment`)

### Reporting

* `GET /api/report.csv` — download all of the user's alerts as CSV

### Pagination convention (`/api/alerts`, `/api/events`, `/api/iocs`, `/api/tickets`)

* Backward-compatible: with **no** `page` / `per_page` / filter query params, the endpoint returns a plain JSON array
* With `page`, `per_page`, or any filter param present, it returns:

```json
{
  "items": [],
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

* `page` defaults to 1 (minimum 1); `per_page` defaults to 25 (clamped to 1–100)

---

## 13. Security Measures

* Session cookies: `HttpOnly`, `SameSite=Lax`, optional `Secure` flag for HTTPS
* CSRF protection via Flask-WTF
* Passwords hashed with Werkzeug (never stored in plaintext)
* Server-restart session invalidation (prevents stale sessions across restarts)
* Rate limiting: 200 requests/day and 50/hour per IP by default
* Brute-force detection at both the **auth layer** (`auth.py`) and the **detection engine** (`detection.py`, via correlation on `failed_login` events)
* Input validation: IP format (`ipaddress` module), port range (1–65535), required fields
* All data access is scoped per `user_id` — no cross-user data leakage
* `.env` and `soc.db` / `*.sqlite*` are excluded from git via `.gitignore`

---

## 14. Testing (`tests/`)

* `test_detection.py` — detection rule/engine tests
* `test_iocs_tracker.py` — IOC extraction tests
* `test_log_analyzer.py` — log normalization tests
* Run with `pytest` (config in `pytest.ini`)

---

## 15. Getting Started

```bash
# 1. Clone and enter the project
git clone <your-repo-url>
cd SentinelSOC

# 2. Create a virtual environment and install dependencies
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste output into SECRET_KEY in .env

# 4. Run
python run.py
```

Then open `http://127.0.0.1:5000`, register an account, log in, and submit a log on the Input page to see the pipeline (analysis → IOCs → threat intel → alerts → tickets) in action on the Dashboard.

For production, run with gunicorn, e.g. `gunicorn run:app`, and set `SESSION_COOKIE_SECURE=true` when serving over HTTPS.

---

## 16. Screenshots

### 16.1 Register Page

<img width="1920" height="1080" alt="Screenshot (335)" src="https://github.com/user-attachments/assets/2ac73541-4dcb-46e1-9a06-cc6e57ce705e" />

### 16.2 Login Page

<img width="1920" height="1080" alt="Screenshot (334)" src="https://github.com/user-attachments/assets/c5708d59-5e5b-4864-b533-95c40262a824" />

### 16.3 Input / Event Submission Page

<img width="1920" height="1080" alt="Screenshot (337)" src="https://github.com/user-attachments/assets/2ace16fc-a61b-4bcd-8875-08a7d37aacb0" />

### 16.4 Dashboard

<img width="1920" height="712" alt="Screenshot (338)" src="https://github.com/user-attachments/assets/a7e94ee4-7f4f-4c8f-ac7f-d886c2d3bb38" />
<img width="1920" height="858" alt="Screenshot (339)" src="https://github.com/user-attachments/assets/9ac02fb3-e284-4dd0-b306-bfc577dac7e7" />
<img width="1920" height="972" alt="Screenshot (340)" src="https://github.com/user-attachments/assets/18b7dbce-df7b-4de7-9f2e-37170e72300e" />

### 16.5 PDF Ticket

<img width="984" height="1080" alt="Screenshot (343)" src="https://github.com/user-attachments/assets/bd3bcd86-d8bd-4de9-ad7f-8a50d777fa66" />

---

## 17. Project File Map

```
SentinelSOC/
├── app/
│   ├── __init__.py       (137 lines)  – app factory, config, extensions
│   ├── auth.py           (629 lines)  – register/login/logout, brute-force detection
│   ├── db.py             (509 lines)  – schema, migrations, connection handling
│   ├── detection.py      (1244 lines) – 8 detection rules + correlation + dedup
│   ├── ioc_tracker.py    (345 lines)  – IOC regex extraction
│   ├── log_analyzer.py   (449 lines)  – raw log normalization
│   ├── routes.py         (1553 lines) – page routes + REST API
│   ├── threat_intel.py   (470 lines)  – threat feed matching, severity boosting
│   └── ticketing.py      (625 lines)  – ticket creation + PDF export
├── templates/            – login.html, register.html, input.html, dashboard.html
├── data/threat_intel.json – local simulated threat intel feed (12 indicators)
├── tests/                – pytest suite
├── run.py                – entry point (host/port/debug from env)
├── requirements.txt
├── pytest.ini
├── .env.example
└── .gitignore
```
