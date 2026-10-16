# SentinelSOC

SentinelSOC is a lightweight **Security Operations Center (SOC) simulator** built with **Flask and SQLite**. It ingests security events (manually, through the API, or from Linux/Windows hosts), normalizes them, extracts IOCs, enriches them with a local threat-intelligence feed, runs detection rules, raises alerts, opens tickets, and shows everything on a dashboard.

- **Backend:** Python 3, Flask (application factory + blueprints)
- **Database:** SQLite (`soc.db`, created automatically on first run)
- **Auth:** session-based login; every record is scoped to the owning user
- **Ingestion:** manual (web form / API) and automated (connectors + collector agents)

> Use SentinelSOC and its collectors only on systems you own or are explicitly authorized to monitor.

## Screenshots

Screenshots were taken from a running instance populated with sample events.

| Login | Register |
| --- | --- |
| ![Login](docs/screenshots/01-login.png) | ![Register](docs/screenshots/02-register.png) |

**Add Security Event (`/input`)**

![Input page](docs/screenshots/03-input.png)

**Dashboard (`/dashboard`)**: summary cards and alert table

![Dashboard](docs/screenshots/04-dashboard.png)

**Security events and log analyzer**

![Events and log analyzer](docs/screenshots/04b-dashboard-events-analyzer.png)

**IOC tracker and IOC intelligence**

![IOCs](docs/screenshots/04c-dashboard-iocs.png)

**SOC ticket queue and recent alert details**

![Tickets](docs/screenshots/04d-dashboard-tickets.png)

**Log connectors (`/connectors`)**: connector creation with the one-time token, and the connector list

![Connector created](docs/screenshots/05-connector-created.png)

![Connector list](docs/screenshots/06-connectors-list.png)

## Features

- User registration and login, with brute-force detection on the login page
- Manual event submission (`/input`) and REST API (`/api/events`)
- Automated log ingestion through per-source connectors (`/connectors`, `POST /api/ingest/<source_id>`)
- Linux collector: log-file tailing and optional systemd journal ingestion with cursor-based resume
- Windows collector: Windows Event Log (Security, System, Defender) through `pywin32`
- Log normalization (event type, IP, port, username extraction)
- IOC extraction (IPs, domains, URLs, emails, MD5/SHA1/SHA256)
- Local threat-intelligence enrichment (`data/threat_intel.json`) with automatic severity boosting
- Event-level detection rules plus correlation rules, tagged with MITRE ATT&CK IDs
- Automatic SOC tickets (`SOC-YYYYMMDD-00001`) with PDF export
- Dashboard and CSV alert report

## Project structure

```
SentinelSOC/
├── agents/
│   ├── linux_collector.py        # Linux log forwarder (Python 3, standard library only)
│   └── windows_collector.py      # Windows Event Log forwarder (Python + pywin32)
├── app/
│   ├── __init__.py               # App factory, config, rate limiter, CSRF
│   ├── auth.py                   # Register / login / logout
│   ├── connectors.py             # Connector management + /api/ingest endpoint
│   ├── db.py                     # Schema + migrations
│   ├── detection.py              # Detection rules + correlation
│   ├── ioc_tracker.py            # IOC extraction
│   ├── log_analyzer.py           # Log normalization
│   ├── routes.py                 # Pages + REST API
│   ├── threat_intel.py           # Threat feed matching
│   └── ticketing.py              # Tickets + PDF export
├── data/threat_intel.json        # Local sample threat feed
├── docs/screenshots/             # Images used in this README
├── templates/                    # login, register, input, dashboard, connectors
├── tests/                        # pytest suite
├── run.py                        # Entry point
├── requirements.txt
├── pytest.ini
└── .env.example
```

## Quick start

```bash
# 1. Enter the project and create a virtual environment
cd SentinelSOC
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
# paste the output as SECRET_KEY in .env

# 4. Run
python run.py
```

Open `http://127.0.0.1:5000`, register, log in, and submit a log on the **Input** page to see the pipeline work.

**Dependencies** (`requirements.txt`): Flask, Flask-Limiter, Flask-WTF, python-dotenv, pytest, reportlab, gunicorn.

### Environment variables (server)

| Variable | Default | Description |
| --- | --- | --- |
| `SECRET_KEY` | *(required)* | Flask secret key; the app refuses to start without it |
| `FLASK_DEBUG` | `false` | Enable Flask debug mode |
| `FLASK_HOST` | `0.0.0.0` | Bind address |
| `PORT` | `5000` | Listen port |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` when serving over HTTPS |

### Production

```bash
gunicorn run:app
```

Serve it behind an HTTPS reverse proxy and set `SESSION_COOKIE_SECURE=true`.

## Ways to send events

| # | Method | Mode | Authentication |
| --- | --- | --- | --- |
| 1 | Web form (`/input`) | Manual | Login session |
| 2 | `POST /api/events` | Manual | Login session + CSRF token |
| 3 | Linux collector | Automated | Connector bearer token |
| 4 | Windows collector | Automated | Connector bearer token |
| 5 | Generic JSON API | Automated | Connector bearer token |
| 6 | Syslog / network device | Automated, via a relay you provide | Connector bearer token |

Methods 3 to 6 all use `POST /api/ingest/<source_id>`.

### Create a connector (methods 3-6)

1. Sign in and open **Log Connectors** (`/connectors`).
2. Enter a name and choose a source type: `linux`, `windows`, `syslog`, or `api`.
3. Create the connector and **copy the token immediately**. It is shown once; only a SHA-256 hash is stored.
4. Note the **Source ID** and the ingestion endpoint (`<server>/api/ingest/<source_id>`).

Connector actions: **Disable / Enable** (pause or resume ingestion) and **Revoke** (delete permanently).

### Method 1: Web form

Log in, open **Input** (`/input`), fill in the event, and submit. The event goes through the full pipeline; check the **Dashboard** for the result.

### Method 2: `POST /api/events`

Used by the Input page. Requires a login session and a CSRF token, so it is meant for the logged-in browser rather than unattended scripts.

| Field | Required | Notes |
| --- | --- | --- |
| `event_type` | yes | e.g. `failed_login` |
| `source_ip` | yes | Must be a valid IP address |
| `message` or `raw_log` | no | Log text |
| `username` | no | |
| `destination_port` | no | Integer |

### Method 3: Linux collector

`agents/linux_collector.py` uses only the Python standard library.

```bash
export SENTINELSOC_URL="https://your-soc-host"
export SENTINELSOC_SOURCE_ID="1"
export SENTINELSOC_TOKEN="your-one-time-token"

python3 agents/linux_collector.py                                   # auto-discover common logs
python3 agents/linux_collector.py /var/log/auth.log /var/log/syslog # explicit files
SENTINELSOC_USE_JOURNAL=1 python3 agents/linux_collector.py          # systemd journal
```

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINELSOC_URL` | *(required)* | Server base URL |
| `SENTINELSOC_SOURCE_ID` | *(required)* | Numeric connector ID |
| `SENTINELSOC_TOKEN` | *(required)* | Connector bearer token |
| `SENTINELSOC_START_MODE` | `hybrid` | `hybrid` = backfill then follow; `live` = only new lines |
| `SENTINELSOC_POLL_SECONDS` | `1` | How often to check for new lines |
| `SENTINELSOC_STATE_FILE` | `~/.sentinelsoc-<id>-checkpoint.json` | Checkpoint file |
| `SENTINELSOC_SEND_INTERVAL` | `0.62` | Minimum seconds between sends (stays under 120 events/min) |
| `SENTINELSOC_LOG_PATHS` | auto-discovery | Colon-separated list of log files |
| `SENTINELSOC_USE_JOURNAL` | `0` | Set `1` / `true` / `yes` to use the systemd journal |
| `SENTINELSOC_HISTORY_DAYS` | `7` | Journal backfill window on first run; `0` skips history |

Behaviour: lines are classified into event types before sending (unrecognized lines are sent as `unknown`); the checkpoint is saved after each accepted line; log rotation is detected; each line gets a deterministic `event_id` so retries do not create duplicates; network errors, HTTP 429 and 5xx are retried, and HTTP 401/403 stops the collector. Both collectors refuse a remote URL that is not `https://` (plain `http://` is accepted only for localhost).

### Method 4: Windows collector

`agents/windows_collector.py` reads the Windows Event Log through **pywin32** and supports the Security, System and Microsoft Defender Operational channels.

```bat
py -m pip install pywin32
set SENTINELSOC_URL=https://your-soc-host
set SENTINELSOC_SOURCE_ID=2
set SENTINELSOC_TOKEN=PASTE_YOUR_ONE_TIME_TOKEN_HERE
py agents\windows_collector.py
```

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINELSOC_URL` / `SENTINELSOC_SOURCE_ID` / `SENTINELSOC_TOKEN` | *(required)* | Connection details |
| `SENTINELSOC_HISTORY_DAYS` | `7` | History window on first run; `0` disables date-based backfill |
| `SENTINELSOC_EVENT_IDS` | unset | Optional comma-separated subset of the default event IDs |
| `SENTINELSOC_POLL_SECONDS` | `5` | Wait when no new events are found (minimum 2) |
| `SENTINELSOC_SEND_INTERVAL` | `0.62` | Minimum spacing between sends |
| `SENTINELSOC_STATE_FILE` | `%LOCALAPPDATA%\SentinelSOC\windows-source-<id>.json` | Checkpoint file |

Default events collected:

| Channel | Event IDs | Meaning |
| --- | --- | --- |
| Security | 4625, 4624, 4672 | Failed / successful logon, privileged logon |
| Security | 4688 | Process creation (needs process-creation auditing) |
| Security | 4697, 4698, 4699 | Service install, scheduled task created / deleted |
| Security | 4719, 1102 | Audit policy changed, Security log cleared |
| Security | 4720, 4722, 4725, 4726 | Account created / enabled / disabled / deleted |
| Security | 5157 | Blocked connection |
| System | 6008, 7036, 7045 | Unexpected shutdown, service state change, service install |
| Defender/Operational | 1116, 1117, 1121, 5007 | Threat detection / remediation, ASR block, configuration change |

> `windows_collector.py` prints a message that mentions `requirements-windows.txt`, but that file is not part of this project. Run `py -m pip install pywin32` directly.

### Method 5: Generic JSON API

```bash
curl -X POST "https://your-soc-host/api/ingest/1" \
  -H "Authorization: Bearer YOUR_SOURCE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "event_id": "app-0001",
        "event_type": "failed_login",
        "message": "Failed password for user test from 203.0.113.10 port 22",
        "timestamp": "2026-10-14T12:00:00Z"
      }'
```

Send a stable `event_id` so retries do not create duplicates.

### Method 6: Syslog / network devices

A connector of type `syslog` can be created, but SentinelSOC has **no built-in syslog listener**. The type is a label; data still arrives through `POST /api/ingest/<source_id>`, so a relay of your own is needed to forward device logs.

## Ingestion API

`POST /api/ingest/<source_id>` with headers `Authorization: Bearer <token>` and `Content-Type: application/json`.

| Field | Required | Notes |
| --- | --- | --- |
| `message` or `raw_log` | yes | Max 16,000 characters |
| `event_type` | no | Default `unknown` |
| `event_id` | no | Idempotency key (max 128 chars) |
| `timestamp` | no | ISO-8601; defaults to server time |
| `platform` | no | Defaults to the connector's source type |
| `source_ip`, `username`, `destination_port`, `status` | no | Extracted from the message when omitted |
| `metadata` | no | Object |

| Status | Meaning |
| --- | --- |
| `201` | Event stored and processed |
| `200` | Duplicate `event_id`, ignored |
| `400` | Body is not a JSON object, or `raw_log` / `message` is missing |
| `401` | Missing or invalid token, or connector unknown / disabled / revoked |
| `413` | `raw_log` longer than 16,000 characters |
| `429` | Too many failed token attempts (10 per minute per IP), per-source limit (120 events/min), or the global rate limit |

Example response:

```json
{"success": true, "event_id": 42, "detected": true, "alert_id": 7, "duplicate": false}
```

## Detection

Each event runs through event-level rules, then correlation rules over recent events. Alerts carry a MITRE ATT&CK ID.

**Generic event rules**

| Rule | Severity | MITRE |
| --- | --- | --- |
| `FAILED_LOGIN` | HIGH | T1110 |
| `BRUTE_FORCE` (event type) | HIGH | T1110 |
| `NETWORK_PORT_SCAN` | HIGH | T1046 |
| `MALWARE_DETECTED` | CRITICAL | T1204 |
| `UNAUTHORIZED_ACCESS` | CRITICAL | T1078 |
| `EXPLOIT_ACTIVITY` | CRITICAL | T1190 |
| `PHISHING_ACTIVITY` | HIGH | T1566 |
| `SUSPICIOUS_LOGIN` | MEDIUM | T1078 |
| `NEW_ACCOUNT_CREATED` | MEDIUM | T1136 |

**Windows rules**

| Rule | Severity | MITRE |
| --- | --- | --- |
| `WINDOWS_SECURITY_LOG_CLEARED` | CRITICAL | T1070.001 |
| `WINDOWS_AUDIT_POLICY_CHANGED` | HIGH | T1562.002 |
| `WINDOWS_SERVICE_INSTALLED` | HIGH | T1543.003 |
| `WINDOWS_SCHEDULED_TASK_CREATED` | MEDIUM | T1053.005 |
| `WINDOWS_ACCOUNT_ENABLED` / `WINDOWS_ACCOUNT_DISABLED` | MEDIUM | T1098 |
| `WINDOWS_ACCOUNT_DELETED` | MEDIUM | T1531 |
| `DEFENDER_CONFIGURATION_CHANGED` | HIGH | T1562.001 |
| `DEFENDER_ASR_BLOCKED` | HIGH | T1059 |
| `WINDOWS_FIREWALL_BLOCKED_CONNECTION` | LOW | T1562.004 |

Windows malware (T1204) and suspicious process creation (T1059) rules also exist.

**Linux rules**

| Rule | Severity | MITRE |
| --- | --- | --- |
| `LINUX_ACCOUNT_DELETED` | MEDIUM | T1531 |
| `LINUX_ACCOUNT_MODIFIED` | MEDIUM | T1098 |
| `LINUX_SSH_KEY_ACTIVITY` | HIGH | T1098.004 |
| `LINUX_SERVICE_INSTALLED` | HIGH | T1543.002 |
| `LINUX_SCHEDULED_TASK_ACTIVITY` | MEDIUM | T1053.003 |
| `LINUX_FIREWALL_RULE_CHANGED` | HIGH | T1562.004 |
| `LINUX_AUDIT_POLICY_CHANGED` | HIGH | T1562.012 |
| `LINUX_SECURITY_LOG_CLEARED` | CRITICAL | T1070.002 |
| `LINUX_PRIVILEGE_ESCALATION` | HIGH | T1068 |
| `LINUX_KERNEL_MODULE_LOADED` | MEDIUM | T1547 |
| `LINUX_MALWARE_DETECTED` | CRITICAL | T1204 |
| `LINUX_ACCESS_DENIED` | MEDIUM | T1222 |
| `LINUX_FIREWALL_BLOCKED_CONNECTION` | LOW | T1562.004 |

**Correlation**

- `BRUTE_FORCE`: 5 or more failed logins from one source IP within 5 minutes
- `SUCCESS_AFTER_BRUTE_FORCE`: a successful login following repeated failures within a 10-minute window
- `PORT_SCAN_PATTERN`: 5 or more distinct destination ports from one source IP

Alerts are de-duplicated for 5 minutes (alert fingerprinting).

**Threat-intelligence enrichment.** Extracted IOCs are matched against `data/threat_intel.json` (a simulated feed with 12 indicators). A match can raise the alert severity; for example, in the screenshots the failed-login alerts from `185.220.101.45` appear as CRITICAL because that IP is in the feed as a CRITICAL indicator.

**IOC types:** IPs, domains, URLs, emails, MD5, SHA1, SHA256.

**Tickets.** Every new alert opens a ticket (`SOC-YYYYMMDD-00001`). Priority follows severity: CRITICAL → P1, HIGH → P2, MEDIUM → P3, LOW → P4. Status values: `OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`. Tickets can be exported as PDF.

## REST API

| Endpoint | Description |
| --- | --- |
| `GET /api/summary` | Alert counts |
| `GET, POST /api/events` | List / submit events |
| `GET /api/alerts`, `/api/alerts/<id>` | Alerts |
| `GET /api/iocs`, `/api/iocs/summary` | IOCs |
| `GET /api/tickets`, `/api/tickets/<id>` | Tickets |
| `PATCH /api/tickets/<id>` | Update ticket status |
| `GET /api/tickets/<id>/pdf` | Download ticket PDF |
| `GET /api/report.csv` | Export alerts as CSV |
| `POST /api/ingest/<source_id>` | Automated ingestion (bearer token) |

All endpoints except `/api/ingest/<source_id>` use the login session. List endpoints accept `page` / `per_page` (default 25, max 100).

## Security notes

- Connector tokens are shown once and stored only as SHA-256 hashes.
- Each connector belongs to one user; its events are attributed to that user.
- Failed token attempts are rate limited per IP (10 per minute).
- HttpOnly, SameSite=Lax session cookies (optional Secure flag); CSRF protection on browser routes; Werkzeug password hashing; passwords must be at least 8 characters; sessions last one hour.
- Request bodies are capped at 1,000,000 bytes.
- `.env` and `soc.db` are excluded from git.

## Testing

```bash
pytest
```

The `tests/` folder contains 49 test functions covering detection, IOC extraction, log analysis, and the Linux and Windows collectors.

## Known limitations

1. **The global rate limit also applies to ingestion.** `app/__init__.py` sets Flask-Limiter defaults of 200 per day and 50 per hour per IP, and the ingestion blueprint is exempt from CSRF but not from the limiter, so a busy collector can receive HTTP 429.
2. No native syslog listener (see Method 6).
3. No agentless Windows collection; the collector must run on each authorized host.
4. Token rotation is not implemented; create a new connector and revoke the old one.
5. SQLite is single-node, which suits a simulator or lab.
