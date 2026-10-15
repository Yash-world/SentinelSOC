# SentinelSOC

SentinelSOC is a lightweight, self-contained **Security Operations Center (SOC) simulator** built with **Flask + SQLite**. It ingests security events (manually, through the API, or from Linux/Windows hosts), normalizes them, extracts IOCs, enriches them with threat intelligence, runs detection rules, raises alerts, opens tickets, and shows everything on a dashboard.

- **Backend:** Python 3, Flask (application factory + blueprints)
- **Database:** SQLite (`soc.db`, auto-created on first run)
- **Auth:** session-based login; every record is scoped to the owning user
- **Ingestion:** manual (web form / API) and automated (connectors + collector agents)

> Use SentinelSOC and its collectors only on systems you own or are explicitly authorized to monitor.

---

## Table of contents

1. [Features](#features)
2. [Project structure](#project-structure)
3. [Quick start](#quick-start)
4. [All connecting methods at a glance](#all-connecting-methods-at-a-glance)
5. [Create a connector (needed for methods 3-6)](#create-a-connector)
6. [Method 1: Manual web form](#method-1-manual-web-form)
7. [Method 2: Manual REST API](#method-2-manual-rest-api)
8. [Method 3: Linux collector](#method-3-linux-collector)
9. [Method 4: Windows collector](#method-4-windows-collector)
10. [Method 5: Generic JSON API (any script or tool)](#method-5-generic-json-api)
11. [Method 6: Syslog / network devices](#method-6-syslog--network-devices)
12. [Ingestion API reference](#ingestion-api-reference)
13. [Verify the connection](#verify-the-connection)
14. [Troubleshooting](#troubleshooting)
15. [Detection overview](#detection-overview)
16. [REST API summary](#rest-api-summary)
17. [Security notes](#security-notes)
18. [Testing](#testing)
19. [Known limitations](#known-limitations)

---

## Features

- User registration and login, with brute-force detection on the login page
- Manual event submission (`/input`) and REST API (`/api/events`)
- **Automated log ingestion** through per-source connectors (`/connectors`, `POST /api/ingest/<source_id>`)
- Linux collector: log-file tailing and optional systemd journal ingestion with cursor-based resume
- Windows collector: Windows Event Log (Security, System, Defender) through `pywin32`
- Log normalization (event type, IP, port, username extraction)
- IOC extraction (IPs, domains, URLs, emails, MD5/SHA1/SHA256) with de-fanging support
- Local threat-intelligence enrichment with automatic severity boosting
- Event-level detection rules plus brute-force and port-scan correlation, tagged with MITRE ATT&CK IDs
- Automatic SOC tickets (`SOC-YYYYMMDD-00001`) with PDF export
- Dashboard and CSV alert report

---

## Project structure

```
microsenital/
├── agents/
│   ├── linux_collector.py        # Linux log forwarder (Python 3, stdlib only)
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
├── templates/                    # login, register, input, dashboard, connectors
├── tests/                        # pytest suite
├── run.py                        # Entry point
├── requirements.txt
└── .env.example
```

---

## Quick start

```bash
# 1. Enter the project and create a virtual environment
cd microsenital
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

Put it behind an HTTPS reverse proxy (nginx, Caddy, etc.) and set `SESSION_COOKIE_SECURE=true`.

---

## All connecting methods at a glance

```
                          ┌──────────────────────────────────────┐
 1. Web form (/input) ──► │                                      │
 2. REST API /api/events ►│                                      │
                          │            SentinelSOC               │
 3. Linux collector ─────►│                                      │
 4. Windows collector ───►│  analyze → IOCs → threat intel →     │
 5. Generic JSON API ────►│  detection rules → alerts → tickets  │
 6. Syslog / network ────►│                                      │
    device (via relay)    └──────────────────────────────────────┘
        (3-6 use POST /api/ingest/<source_id> with a bearer token)
```

| # | Method | Mode | Authentication | Best for |
| --- | --- | --- | --- | --- |
| 1 | Web form (`/input`) | Manual | Login session | Demos, testing, one-off logs |
| 2 | `POST /api/events` | Manual | Login session + CSRF token | Scripted use from the logged-in browser |
| 3 | Linux collector | Automated | Connector bearer token | Continuous forwarding from Linux hosts |
| 4 | Windows collector | Automated | Connector bearer token | Continuous forwarding from Windows hosts |
| 5 | Generic JSON API | Automated | Connector bearer token | Custom apps, scripts, other tools |
| 6 | Syslog / network device | Automated, via a relay | Connector bearer token | Firewalls, routers, switches (see [limits](#method-6-syslog--network-devices)) |

Methods 3 to 6 all end at the same endpoint, `POST /api/ingest/<source_id>`, so they share the same token, rate limits and response codes.

---

## Create a connector

Methods 3 to 6 need a **connector**, which gives you a **Source ID** and a **one-time bearer token**.

1. Sign in to SentinelSOC and open **Log Connectors** (`/connectors`).
2. Enter a name and choose the source type: `linux`, `windows`, `syslog` (Syslog / Network Device), or `api` (Generic JSON API).
3. Click **Create Connector** and **copy the token immediately**. It is shown only once; only a SHA-256 hash is stored.
4. Note the **Source ID** and the **Ingestion Endpoint** (`<server>/api/ingest/<source_id>`) shown on the page.

You will need three values wherever the sender runs:

| Variable | Value |
| --- | --- |
| `SENTINELSOC_URL` | Base URL of your SentinelSOC server, e.g. `https://soc.example.com` (no trailing slash) |
| `SENTINELSOC_SOURCE_ID` | The numeric Source ID of the connector |
| `SENTINELSOC_TOKEN` | The one-time token |

Connector actions on the page: **View Details**, **Disable / Enable** (stops or resumes ingestion without deleting), and **Revoke** (deletes the connector permanently).

> **HTTPS is enforced in both collectors.** They refuse to run against a remote URL that is not `https://`. Plain `http://` is accepted only for `localhost`, `127.0.0.1` or `::1`.

> A lost token cannot be recovered (only its hash is stored). Create a new connector and revoke the old one.

---

## Method 1: Manual web form

Best for demos and testing; no connector needed.

1. Log in and open **Input** (`/input`).
2. Paste a log line or fill in the event fields and submit.
3. The event goes through the full pipeline (analysis, IOCs, threat intel, detection, alert, ticket).
4. Open **Dashboard** (`/dashboard`) to see the result.

---

## Method 2: Manual REST API

`POST /api/events` is the endpoint the Input page uses. It authenticates with your **login session** and is **CSRF-protected**, so it is meant for the logged-in browser, not for unattended scripts. For scripts and agents, use a connector (Methods 3 to 6).

| Field | Required | Notes |
| --- | --- | --- |
| `event_type` | yes | e.g. `failed_login` |
| `source_ip` | yes | Must be a valid IP address |
| `message` or `raw_log` | no | Log text |
| `username` | no | |
| `destination_port` | no | Integer |

Listing endpoints (`GET /api/events`, `/api/alerts`, ...) are in the [REST API summary](#rest-api-summary).

---

## Method 3: Linux collector

`agents/linux_collector.py` forwards Linux logs to SentinelSOC. **Python 3, standard library only; no `pip install` needed.**

### Requirements

- Python 3 on the Linux host
- Read access to the logs you want to forward
- Network access from the host to the SentinelSOC server

### Step 1: Copy the collector to the host

```bash
scp agents/linux_collector.py user@linux-host:/opt/sentinelsoc/
```

### Step 2: Set the connection variables

```bash
export SENTINELSOC_URL="https://your-soc-host"
export SENTINELSOC_SOURCE_ID="1"
export SENTINELSOC_TOKEN="your-one-time-token"
```

### Step 3: Choose how to read logs (three ways)

**A. Auto-discovery (no arguments).** The collector looks for readable common files and reports the ones it cannot read, such as `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, `/var/log/messages`, `/var/log/audit/audit.log`, UFW, Fail2ban, kernel and cron logs.

```bash
python3 /opt/sentinelsoc/linux_collector.py
```

**B. Explicit files, as arguments.**

```bash
python3 /opt/sentinelsoc/linux_collector.py /var/log/auth.log /var/log/syslog /var/log/audit/audit.log
```

**C. Explicit files, through an environment variable** (colon-separated list). When set, it takes priority over command-line arguments.

```bash
export SENTINELSOC_LOG_PATHS="/var/log/auth.log:/var/log/syslog"
python3 /opt/sentinelsoc/linux_collector.py
```

**D. systemd journal**, for systems where security logs are available only through the journal:

```bash
export SENTINELSOC_USE_JOURNAL=1
python3 /opt/sentinelsoc/linux_collector.py
```

Journal mode runs `journalctl --follow --output=json`, resumes from a saved cursor, and on the first run backfills the previous 7 days by default (`SENTINELSOC_HISTORY_DAYS=0` skips history). It needs `journalctl` and permission to read the journal. Avoid collecting the same events from both the journal and duplicated log files unless duplicate ingestion is acceptable.

If you get a permission error, run as a user that can read the file (for example a member of the `adm` group on Debian/Ubuntu) or use `sudo`. Prefer least-privilege read access over running as root.

### Linux collector options

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINELSOC_URL` | *(required)* | Server base URL |
| `SENTINELSOC_SOURCE_ID` | *(required)* | Numeric connector ID |
| `SENTINELSOC_TOKEN` | *(required)* | Connector bearer token |
| `SENTINELSOC_START_MODE` | `hybrid` | `hybrid` = backfill existing lines, then follow new ones. `live` = only new lines |
| `SENTINELSOC_POLL_SECONDS` | `1` | How often to check for new lines |
| `SENTINELSOC_STATE_FILE` | `~/.sentinelsoc-<id>-checkpoint.json` | Checkpoint file (file offsets/inodes and the journal cursor) |
| `SENTINELSOC_SEND_INTERVAL` | `0.62` | Minimum seconds between sends (keeps under the 120 events/min per-source limit) |
| `SENTINELSOC_LOG_PATHS` | auto-discovery | Colon-separated explicit list of log files |
| `SENTINELSOC_USE_JOURNAL` | `0` | Set `1` / `true` / `yes` to use the systemd journal |
| `SENTINELSOC_HISTORY_DAYS` | `7` | Journal backfill window on first run; `0` skips history |

### Behaviour worth knowing

- **Classification:** the collector classifies common SSH, sudo, account, service, cron, firewall, audit and antivirus lines into event types before sending. Unrecognized lines are still ingested as `unknown`, so the evidence stays searchable.
- **Checkpointing:** the offset is saved after each accepted line, so a restart resumes where it stopped. Do not delete the checkpoint file unless you want the file replayed.
- **Log rotation/truncation:** detected through inode/size changes; the collector follows the new file from its start.
- **Idempotent retries:** each line gets a deterministic `event_id` (hash of path, inode, offset and text), so a retry never creates a duplicate event.
- **Retries:** network errors, HTTP 429 and 5xx are retried every 5 seconds. HTTP 401/403 stops the collector with a clear message.
- **Rejected events:** permanent HTTP rejections are written to `<checkpoint>.rejected.jsonl` before the stream advances. Review that file for payload problems.
- **Timestamps:** parsed from an ISO-8601 prefix or the classic `Oct 12 19:22:01` syslog prefix; otherwise the current time is used.

### Run it as a service (systemd)

Create `/etc/systemd/system/sentinelsoc-collector.service`:

```ini
[Unit]
Description=SentinelSOC Linux log collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinelsoc
Environment=SENTINELSOC_URL=https://your-soc-host
Environment=SENTINELSOC_SOURCE_ID=1
EnvironmentFile=/etc/sentinelsoc/collector.env
ExecStart=/usr/bin/python3 /opt/sentinelsoc/linux_collector.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Keep the secret out of the unit file:

```bash
sudo mkdir -p /etc/sentinelsoc
echo 'SENTINELSOC_TOKEN=your-one-time-token' | sudo tee /etc/sentinelsoc/collector.env
sudo chmod 600 /etc/sentinelsoc/collector.env
```

Then create the user and start it:

```bash
sudo useradd --system --create-home sentinelsoc
sudo usermod -aG adm sentinelsoc           # read access to /var/log/auth.log on Debian/Ubuntu
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelsoc-collector
sudo systemctl status sentinelsoc-collector
journalctl -u sentinelsoc-collector -f
```

---

## Method 4: Windows collector

`agents/windows_collector.py` reads selected events from the Windows Event Log API through **`pywin32`** (no PowerShell) and forwards them to SentinelSOC. It supports the Security, System and Microsoft Defender Operational channels when they exist and are readable.

### Events collected by default

| Channel | Event IDs | What they indicate |
| --- | --- | --- |
| Security | 4625, 4624, 4672 | Failed / successful logon, privileged logon |
| Security | 4688 | Process creation (needs process-creation auditing) |
| Security | 4697, 4698, 4699 | Service install, scheduled task created / deleted |
| Security | 4719, 1102 | Audit policy changed, Security log cleared |
| Security | 4720, 4722, 4725, 4726 | Account created / enabled / disabled / deleted |
| Security | 5157 | Windows Filtering Platform blocked a connection |
| System | 6008, 7036, 7045 | Unexpected shutdown, service state change, service install |
| Microsoft-Windows-Windows Defender/Operational | 1116, 1117, 1121, 5007 | Threat detection / remediation, ASR block, configuration change |

Event 5156 (allowed connections) is excluded on purpose because of its volume. The collector does not change audit policies; events such as 4688, 4698 and 5157 appear only when the matching Windows audit settings are enabled.

### Step 1: Create a Windows connector

Follow [Create a connector](#create-a-connector) and choose **Windows**.

### Step 2: Install Python and pywin32

Install Python 3.10+ on the endpoint, open **Command Prompt as Administrator**, go to the project folder, then run:

```bat
py -m pip install pywin32
```

> The collector's error message mentions `requirements-windows.txt`, but that file is not included in this project. Installing `pywin32` directly does the same job. You can create the file yourself with a single line, `pywin32`, if you want the message to be accurate.

### Step 3: Set variables and run

In the same Command Prompt window:

```bat
set SENTINELSOC_URL=https://your-soc-host
set SENTINELSOC_SOURCE_ID=2
set SENTINELSOC_TOKEN=PASTE_YOUR_ONE_TIME_TOKEN_HERE
py agents\windows_collector.py
```

Use `http://127.0.0.1:5000` only when the server runs on the same computer for local testing. Remote servers must use HTTPS with a valid certificate. The variables apply only to that window.

### Windows collector options

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINELSOC_URL` | *(required)* | Server base URL |
| `SENTINELSOC_SOURCE_ID` | *(required)* | Numeric connector ID |
| `SENTINELSOC_TOKEN` | *(required)* | Connector bearer token |
| `SENTINELSOC_HISTORY_DAYS` | `7` | History window on first run; `0` disables date-based backfill |
| `SENTINELSOC_EVENT_IDS` | unset | Optional comma-separated subset of the default IDs, e.g. `4625,4624,4688,1102` |
| `SENTINELSOC_POLL_SECONDS` | `5` | Wait when no new events are found (minimum 2 seconds) |
| `SENTINELSOC_SEND_INTERVAL` | `0.62` | Minimum spacing between sends (stays under 120 events/min) |
| `SENTINELSOC_STATE_FILE` | `%LOCALAPPDATA%\SentinelSOC\windows-source-<id>.json` | Checkpoint file with per-channel positions |

### Behaviour worth knowing

- The first run reads the last seven days by default, then follows new records; checkpoints are saved after successful sends.
- Provider, computer, channel, event ID, record ID and structured event data are kept in the raw evidence.
- HTTP 429/5xx and network errors are retried; HTTP 401/403 stops the collector.
- On busy endpoints, tune `SENTINELSOC_EVENT_IDS` and `SENTINELSOC_HISTORY_DAYS` to stay under the ingestion cap.
- The collector does not install itself as a Windows service. For monitoring after reboot, deploy it through your organization's approved service-management process.

---

## Method 5: Generic JSON API

Any script, application or tool that can send an HTTP POST can feed SentinelSOC. Create a connector of type **Generic JSON API** (`api`), then send JSON to its ingestion endpoint.

### curl

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

### Python (standard library)

```python
import json
import urllib.request

URL = "https://your-soc-host/api/ingest/1"
TOKEN = "YOUR_SOURCE_TOKEN"

payload = {
    "event_id": "app-0002",
    "event_type": "failed_login",
    "message": "Failed password for user test from 203.0.113.10 port 22",
}

req = urllib.request.Request(
    URL,
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
    },
    method="POST",
)

with urllib.request.urlopen(req, timeout=10) as resp:
    print(resp.status, resp.read().decode())
```

Always send a stable `event_id` so retries do not create duplicates. `203.0.113.10` is a documentation-reserved address, not a real indicator.

---

## Method 6: Syslog / network devices

You can create a connector of type **Syslog / Network Device** (`syslog`), but **SentinelSOC has no built-in syslog listener** (no UDP/TCP 514 receiver). The type is a label for the connector; the data still arrives through `POST /api/ingest/<source_id>`.

To bring in logs from a firewall, router or switch, put a small relay between the device and SentinelSOC. The relay receives or reads the device's syslog and forwards each line over HTTPS.

A minimal example: your syslog server (rsyslog, syslog-ng, etc.) writes the device logs to a file, and this script forwards new lines from standard input:

```python
#!/usr/bin/env python3
"""Forward lines from stdin to SentinelSOC. Usage:
   tail -F /var/log/network-devices.log | python3 forward.py
"""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

URL = os.environ["SENTINELSOC_URL"].rstrip("/")
SOURCE_ID = os.environ["SENTINELSOC_SOURCE_ID"]
TOKEN = os.environ["SENTINELSOC_TOKEN"]
ENDPOINT = f"{URL}/api/ingest/{SOURCE_ID}"

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    body = {
        "event_id": "syslog-" + hashlib.sha256(line.encode()).hexdigest(),
        "event_type": "unknown",
        "message": line[:16000],
    }
    req = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code} for line: {line[:80]}", file=sys.stderr)
    except urllib.error.URLError as exc:
        print(f"Network error: {exc}", file=sys.stderr)
    time.sleep(0.62)  # stay under 120 events/min per source
```

Notes:

- Lines are sent as `event_type: unknown`; the server tries to classify them from the message text.
- Identical lines hash to the same `event_id`, so a repeated identical line is treated as a duplicate. Include a timestamp in the hash if you need every repeat stored.
- This example does not retry on failure. For production, add a retry loop and a local spool.

---

## Ingestion API reference

`POST /api/ingest/<source_id>`

**Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`

| Field | Required | Notes |
| --- | --- | --- |
| `message` or `raw_log` | yes | Max 16,000 characters |
| `event_type` | no | Default `unknown`; the analyzer may normalize it from the message |
| `event_id` | no | Idempotency key (max 128 chars). Strongly recommended |
| `timestamp` | no | ISO-8601; defaults to server time |
| `platform` | no | Defaults to the connector's source type |
| `source_ip`, `username`, `destination_port`, `status` | no | Extracted from the message when omitted |
| `metadata` | no | Object; `metadata.platform` is used if `platform` is missing |

| Status | Meaning |
| --- | --- |
| `201` | Event stored and processed |
| `200` | Duplicate `event_id`, ignored (`"duplicate": true`) |
| `400` | Body is not a JSON object, or `raw_log` / `message` is missing |
| `401` | Missing or invalid token, or connector unknown / disabled / revoked |
| `413` | `raw_log` longer than 16,000 characters |
| `429` | Too many failed token attempts (10 per minute per IP), per-source limit (120 events/min) exceeded, or the global rate limit (see [Known limitations](#known-limitations)) |

A successful response looks like:

```json
{"success": true, "event_id": 42, "detected": true, "alert_id": 7, "duplicate": false}
```

---

## Verify the connection

1. **Connectors page:** the connector's **Last Seen** time and **Events** counter should update.
2. **Dashboard:** new events and alerts appear for your user.
3. **Manual test** (replace the Source ID and token):

```bash
curl -X POST "http://127.0.0.1:5000/api/ingest/1" \
  -H "Authorization: Bearer YOUR_SOURCE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event_id":"test-001","event_type":"failed_login","message":"Failed password for user test from 203.0.113.10 port 22"}'
```

You should get `201`. Sending the same `event_id` again returns `200` with `"duplicate": true`.

---

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `Use HTTPS for remote SentinelSOC URLs` | Use an `https://` URL, or `http://localhost` for local testing |
| `Set SENTINELSOC_URL, SENTINELSOC_SOURCE_ID and SENTINELSOC_TOKEN` | A variable is missing, or the Source ID is not numeric |
| `Collector token rejected (HTTP 401/403)` | Wrong Source ID or token, or the connector was disabled/revoked. Create a new connector |
| `Cannot open /var/log/auth.log` | Wrong path (try `/var/log/secure`) or no read permission |
| `journalctl was requested but is not installed` | Install systemd tools, or unset `SENTINELSOC_USE_JOURNAL` |
| Windows: `Missing pywin32` | Run `py -m pip install pywin32` |
| Windows: nothing is forwarded | Not running as Administrator, the relevant audit policy is off, or there are no matching events in the history window |
| Collector keeps printing `HTTP 429; retrying` | See [Known limitations](#known-limitations), item 1 |
| `HTTP 401` from curl | Missing `Bearer ` prefix, wrong token, or wrong Source ID |
| Events arrive but no alerts | The line may not match a detection rule; it is still stored as an event |

---

## Detection overview

| Rule | Severity | MITRE |
| --- | --- | --- |
| `FAILED_LOGIN` | HIGH | T1110 |
| `BRUTE_FORCE` | HIGH | T1110 |
| `NETWORK_PORT_SCAN` | HIGH | T1046 |
| `MALWARE_DETECTED` | CRITICAL | T1204 |
| `UNAUTHORIZED_ACCESS` | CRITICAL | T1078 |
| `EXPLOIT_ACTIVITY` | CRITICAL | T1190 |
| `PHISHING_ACTIVITY` | HIGH | T1566 |
| `SUSPICIOUS_LOGIN` | MEDIUM | T1078 |
| `WINDOWS_SECURITY_LOG_CLEARED` | CRITICAL | T1070.001 |
| `WINDOWS_AUDIT_POLICY_CHANGED` | HIGH | T1562.002 |
| `WINDOWS_SERVICE_INSTALLED` | HIGH | T1543.003 |
| `WINDOWS_SCHEDULED_TASK_CREATED` | MEDIUM | T1053.005 |
| `DEFENDER_CONFIGURATION_CHANGED` | HIGH | T1562.001 |
| `WINDOWS_SUSPICIOUS_PROCESS` | HIGH | T1059 (heuristic) |

Correlation: 5+ failed logins from one IP within 5 minutes (`BRUTE_FORCE`) and 5+ distinct destination ports from one IP (`PORT_SCAN_PATTERN`). Alerts are de-duplicated for 5 minutes, and each new alert opens a ticket (CRITICAL → P1, HIGH → P2, MEDIUM → P3, LOW → P4).

Linux coverage is a practical baseline, not a guarantee. The collector can only forward what the host records, so enabling auditd rules, firewall logging, antivirus logging and process auditing is an administrator decision. Tune the heuristics for your environment.

---

## REST API summary

| Endpoint | Description |
| --- | --- |
| `GET /api/summary` | Alert counts |
| `GET, POST /api/events` | List / submit events |
| `GET /api/alerts`, `/api/alerts/<id>` | Alerts |
| `GET /api/iocs`, `/api/iocs/summary` | IOCs |
| `GET /api/tickets`, `/api/tickets/<id>` | Tickets |
| `PATCH /api/tickets/<id>` | Update ticket status (`OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`) |
| `GET /api/tickets/<id>/pdf` | Download ticket PDF |
| `GET /api/report.csv` | Export alerts as CSV |
| `POST /api/ingest/<source_id>` | Automated ingestion (bearer token) |

All endpoints except `/api/ingest/<source_id>` use the login session. List endpoints accept filters and `page` / `per_page` (default 25, max 100).

---

## Security notes

- Connector tokens are shown once and stored only as SHA-256 hashes.
- Each connector belongs to one user; its events are attributed to that user.
- Disable or revoke a connector to stop ingestion immediately.
- Failed token attempts are rate limited per IP (10 per minute).
- HttpOnly, SameSite=Lax session cookies (optional Secure flag); CSRF protection on browser routes; Werkzeug password hashing; per-user data isolation on every query.
- Use HTTPS for any non-local deployment, and keep token files, checkpoint files and `.rejected.jsonl` files private.
- `.env` and `soc.db` are excluded from git.
- The ingestion path is synchronous and lightweight. For larger deployments add a durable queue, a bounded retry spool, TLS termination, monitoring and retention controls.

---

## Testing

```bash
pytest
```

Covers detection rules, IOC extraction, log normalization and both collectors' classification logic.

---

## Known limitations

1. **The global rate limit also applies to ingestion.** `app/__init__.py` sets Flask-Limiter defaults of `200 per day` and `50 per hour` per IP. The ingestion blueprint is exempt from CSRF but **not** from the limiter, so a busy collector can hit HTTP 429 after about 50 requests in an hour. The per-source 120/min throttle already protects ingestion, so exempt the blueprint right after it is registered:

   ```python
   csrf.exempt(ingestion_bp)
   limiter.exempt(ingestion_bp)
   ```

2. **No native syslog listener.** Network devices need a relay (see Method 6).
3. **No agentless Windows collection.** There is no WinRM/WMI pull; the collector must run on each authorized host. PowerShell script-block (4104) and Sysmon events are not collected by default.
4. **Token rotation is not implemented.** If a token is lost, create a new connector and revoke the old one.
5. **Pending-token display is in memory.** The one-time token screen uses server memory, so it is not suitable for multi-worker deployments without shared storage.
6. **Single-node SQLite.** Fine for a simulator or lab; use a server database and a queue for real workloads.

