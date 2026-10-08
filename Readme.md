# 🛡️ SentinelSOC

> A self-contained **Security Operations Center (SOC) simulator** built with **Flask + SQLite**.
> Feed it a security event or a raw log line and watch it get parsed, enriched with threat intelligence, matched against detection rules, turned into an **alert**, and escalated into an **incident ticket**, all on a live dashboard.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57)
![Tests](https://img.shields.io/badge/Tests-pytest-green)
![MITRE](https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-red)

---

## 📑 Table of Contents

1. [What is SentinelSOC?](#1--what-is-sentinelsoc)
2. [Who is it for?](#2--who-is-it-for)
3. [Screenshots](#3--screenshots)
4. [Key Features](#4--key-features)
5. [SOC Concepts in 60 Seconds](#5--soc-concepts-in-60-seconds)
6. [Quick Start](#6--quick-start)
7. [Step-by-Step Walkthrough](#7--step-by-step-walkthrough)
8. [Ready-to-Use Test Scenarios](#8--ready-to-use-test-scenarios)
9. [How It Works (Pipeline)](#9--how-it-works-pipeline)
10. [Detection Rules](#10--detection-rules)
11. [Threat Intelligence Feed](#11--threat-intelligence-feed)
12. [Tickets & Reports](#12--tickets--reports)
13. [REST API Reference](#13--rest-api-reference)
14. [Configuration](#14--configuration)
15. [Database Overview](#15--database-overview)
16. [Project Structure](#16--project-structure)
17. [Security Measures](#17--security-measures)
18. [Testing](#18--testing)
19. [Deployment](#19--deployment)
20. [Troubleshooting](#20--troubleshooting)
21. [FAQ](#21--faq)
22. [Limitations & Roadmap](#22--limitations--roadmap)
23. [Further Reading](#23--further-reading)

---

## 1. 🔍 What is SentinelSOC?

In a real company, a SOC team watches thousands of security events (failed logins, port scans, malware detections) and has to decide which ones matter. SentinelSOC reproduces that workflow in a small web app you can run on your laptop.

You submit an event, for example:

```
Failed login for user admin from 185.220.101.45 port 22
```

and SentinelSOC automatically:

1. **Normalizes** the text into structured fields (event type, IP, username, port)
2. **Extracts indicators of compromise (IOCs)** such as IPs, domains, URLs and file hashes
3. **Checks them against a threat-intelligence feed** (and raises severity if there's a hit)
4. **Runs detection rules** mapped to MITRE ATT&CK
5. **Raises an alert** (and de-duplicates repeats)
6. **Opens an incident ticket** with a priority (P1–P4) that you can export as PDF
7. **Shows everything on a dashboard**

Every user gets a private workspace, so several people can use one instance without seeing each other's data.

---

## 2. 👥 Who is it for?

| You are…                      | How SentinelSOC helps                                          |
| ----------------------------- | -------------------------------------------------------------- |
| A student learning blue-team  | See how events become alerts, tickets and ATT&CK techniques    |
| A job seeker                  | A portfolio project that covers detection, enrichment and ticketing |
| A trainer / teacher           | A safe sandbox to demo SOC workflows without real infrastructure |
| A developer                   | A clean Flask app (factory + blueprints, REST API, tests) to learn from or extend |

> ⚠️ It is a **simulator**, not a production SIEM. Events are entered by hand and the threat feed is a small sample.

---

## 3. 📸 Screenshots

### 3.1 Register page
Create an account (name, email, password with at least 8 characters).

<img width="1920" height="1080" alt="Register page" src="https://github.com/user-attachments/assets/2ac73541-4dcb-46e1-9a06-cc6e57ce705e" />

### 3.2 Login page
Sign in. Repeated failures from one IP are themselves detected as a brute-force attack.

<img width="1920" height="1080" alt="Login page" src="https://github.com/user-attachments/assets/c5708d59-5e5b-4864-b533-95c40262a824" />

### 3.3 Input / event submission page
Pick an event type, enter the source IP, optional username/port/status, or paste a raw log line.

<img width="1920" height="1080" alt="Input page" src="https://github.com/user-attachments/assets/2ace16fc-a61b-4bcd-8875-08a7d37aacb0" />

### 3.4 Dashboard
Summary counters, alerts, events, IOCs and tickets in one place.

<img width="1920" height="712" alt="Dashboard overview" src="https://github.com/user-attachments/assets/a7e94ee4-7f4f-4c8f-ac7f-d886c2d3bb38" />
<img width="1920" height="858" alt="Dashboard alerts and IOCs" src="https://github.com/user-attachments/assets/9ac02fb3-e284-4dd0-b306-bfc577dac7e7" />
<img width="1920" height="972" alt="Dashboard tickets" src="https://github.com/user-attachments/assets/18b7dbce-df7b-4de7-9f2e-37170e72300e" />

### 3.5 PDF incident ticket
Every ticket can be downloaded as a formatted PDF.

<img width="984" height="1080" alt="PDF ticket" src="https://github.com/user-attachments/assets/bd3bcd86-d8bd-4de9-ad7f-8a50d777fa66" />

---

## 4. ✨ Key Features

| Area               | What you get                                                                                   |
| ------------------ | ---------------------------------------------------------------------------------------------- |
| Log analysis       | Free-text logs → structured events (type, IP, port, username)                                  |
| Detection          | 8 event-level rules + 2 correlation rules, each mapped to a MITRE ATT&CK technique             |
| IOC tracking       | IPs, domains, URLs, emails, MD5 / SHA1 / SHA256, de-duplicated and linked to events            |
| Threat intel       | Local feed matching (feed values stored in de-fanged form such as `evil[.]com` are normalized before comparing), automatic severity boost  |
| Alert hygiene      | 5-minute de-duplication so one attack doesn't create 100 identical alerts                      |
| Ticketing          | Auto-created tickets `SOC-YYYYMMDD-00001`, P1–P4 priority, status workflow, PDF export         |
| Analyst response   | Write your own response / resolution notes on any ticket (up to 10,000 characters); saved with the ticket and printed in the PDF |
| Dashboard          | Counters, alert/event/IOC/ticket tables                                                        |
| API & reporting    | JSON REST API with filters + pagination, CSV export of alerts                                  |
| Multi-user         | Registration/login, every query scoped to the logged-in user                                   |
| Hardening          | CSRF protection, rate limiting, hashed passwords, secure cookie flags, session expiry          |

---

## 5. 🧠 SOC Concepts in 60 Seconds

| Term                | Meaning in this project                                                                 |
| ------------------- | --------------------------------------------------------------------------------------- |
| **Event**           | One thing that happened, e.g. "failed login from 10.0.0.5"                              |
| **IOC**             | Indicator of Compromise: an IP, domain, URL, email or file hash tied to malicious activity |
| **Threat intel**    | Known-bad indicators with context (malware family, severity, confidence)                |
| **Detection rule**  | A condition that turns an event into an alert                                           |
| **Correlation**     | Looking at *many* events together (e.g. 5 failed logins in 5 minutes = brute force)     |
| **Alert**           | "Something suspicious happened", with a severity: LOW / MEDIUM / HIGH / CRITICAL        |
| **Ticket**          | A tracked incident an analyst works through: OPEN → IN_PROGRESS → RESOLVED → CLOSED     |
| **MITRE ATT&CK**    | A public catalogue of attacker techniques (e.g. T1110 = Brute Force)                    |
| **De-fanged IOC**   | A safe-to-share form such as `evil[.]com`. The threat feed uses it, and SentinelSOC normalizes it to `evil.com` when matching |

---

## 6. 🚀 Quick Start

**Requirements:** Python 3 (the project was developed on Python 3.13; 3.10+ is expected to work) and `pip`. No database server or external service is needed.

### Step 1: Get the code

```bash
git clone <your-repo-url>
cd SentinelSOC
```

### Step 2: Create a virtual environment and install dependencies

```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1
# Windows (cmd)
venv\Scripts\activate

pip install -r requirements.txt
```

### Step 3: Configure environment variables

```bash
cp .env.example .env          # Windows: copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Open `.env` and paste the generated value as `SECRET_KEY`:

```env
SECRET_KEY=<paste-the-generated-64-character-value-here>
FLASK_DEBUG=false
FLASK_HOST=127.0.0.1
```

> The app **refuses to start** without a `SECRET_KEY`.

### Step 4: Run it

```bash
python run.py
```

Open **http://127.0.0.1:5000** → you'll be redirected to the login page. The database (`soc.db`) is created automatically on first run.

---

## 7. 🧭 Step-by-Step Walkthrough

1. **Register** at `/register`. You are *not* logged in automatically.
2. **Log in** at `/login`. You land on the input page.
3. **Submit an event** on `/input`:
   - Choose an **event type** (Normal Login, Failed Login, Suspicious Login, Port Scan, Network Scan, Malware, Ransomware)
   - Enter the **source IP** (required, must be a valid IPv4/IPv6 address)
   - Optionally add **username**, **destination port** (1–65535), **status** (success / failed / suspicious / blocked / malicious) and a **raw log / message**
4. **Read the result**: the response tells you whether an alert fired, which IOCs were found and whether threat intel matched.
5. **Open the dashboard** at `/dashboard`:
   - Summary counters (total / critical / high / medium / open)
   - Alerts with severity, rule, MITRE ID and threat-intel flag
   - Extracted IOCs
   - Tickets, where you can open the ticket details, **write and save your response / resolution notes**, change status and download a PDF
6. **Write your response to a ticket**: open a ticket on the dashboard, type your findings or the action you took in the **response box**, and click **Save**. Your text is stored with the ticket, shown in its details, and printed in the PDF under *Analyst Response / Resolution*. Writing a response is optional, and you can edit it later.
7. **Export a report**: `GET /api/report.csv` downloads all your alerts as CSV.

---

## 8. 🧪 Ready-to-Use Test Scenarios

Use these on the Input page (or via the API) to see each part of the pipeline.

### Scenario A: Threat-intel hit raises severity
| Field       | Value                                   |
| ----------- | --------------------------------------- |
| Event type  | `failed_login`                          |
| Source IP   | `185.220.101.45`                        |
| Username    | `admin`                                 |
| Message     | `Failed login for user admin`           |

**Expect:** a `FAILED_LOGIN` alert (normally HIGH) **boosted to CRITICAL** because the IP is a known C2 server in the feed (malware family *DarkComet*), plus a P1 ticket.

### Scenario B: Brute-force correlation
Submit a `failed_login` from the **same IP** (e.g. `10.0.0.5`) **5 times within 5 minutes**.

**Expect:** each event raises `FAILED_LOGIN`, and the 5th also raises a `BRUTE_FORCE` correlation alert (T1110).

### Scenario C: Port-scan pattern
Submit `port_scan` events from `10.0.0.9` targeting **5 different destination ports** (22, 80, 443, 3389, 8080).

**Expect:** `NETWORK_PORT_SCAN` alerts plus a `PORT_SCAN_PATTERN` correlation alert (T1046).

### Scenario D: Malware with IOC extraction
| Field      | Value                                                                 |
| ---------- | --------------------------------------------------------------------- |
| Event type | `malware`                                                             |
| Source IP  | `192.168.1.20`                                                        |
| Message    | `Malware detected: trojan beaconing to update-microsoft-security.net` |

**Expect:** a CRITICAL `MALWARE_DETECTED` alert, a domain IOC, and a threat-intel match (*SocGholish*).

> Write the domain in its normal form (`.net`). A de-fanged domain typed into the message (`...security[.]net`) is **not** picked up by the IOC extractor; de-fang handling only applies when matching against the feed.

### Scenario E: Hash match
Message: `File hash 5d41402abc4b2a76b9719d911017c592 flagged on host`
**Expect:** an MD5 IOC matched against *LockBit* in the feed.

### Scenario F: De-duplication
Submit the *exact same* event twice within 5 minutes. **Expect:** the second submission reuses the existing alert instead of creating a duplicate.

### Scenario G: Login brute force against the app itself
Enter a wrong password on the login page **5 times within 5 minutes**.
**Expect:** a HIGH `BRUTE_FORCE_LOGIN` alert (T1110) is raised for that IP.

---

## 9. ⚙️ How It Works (Pipeline)

```
        Raw log or form input
                 │
                 ▼
   ┌──────────────────────────┐
   │ 1. Log Analyzer          │  normalizes event type, extracts IP / port / username
   └────────────┬─────────────┘
                ▼
   ┌──────────────────────────┐
   │ 2. IOC Tracker           │  IPs, domains, URLs, emails, MD5/SHA1/SHA256
   └────────────┬─────────────┘
                ▼
   ┌──────────────────────────┐
   │ 3. Threat Intel          │  match against feed, de-fang aware
   └────────────┬─────────────┘
                ▼
   ┌──────────────────────────┐
   │ 4. Detection Engine      │  8 event rules + brute-force & port-scan correlation
   └────────────┬─────────────┘
                ▼
   ┌──────────────────────────┐
   │ 5. Enrich + Deduplicate  │  boost severity, SHA-256 fingerprint, 5-min window
   └────────────┬─────────────┘
                ▼
   ┌──────────────────────────┐
   │ 6. Ticketing             │  SOC-YYYYMMDD-00001, priority P1–P4
   └────────────┬─────────────┘
                ▼
        Dashboard · API · PDF · CSV
```

**Event type normalization examples**

| Phrase in the log                                   | Becomes                  |
| --------------------------------------------------- | ------------------------ |
| "failed login", "login failed", "invalid password"  | `failed_login`           |
| "authentication failure", "auth failure"            | `authentication_failure` |
| "port scan", "nmap scan"                            | `port_scan`              |
| "malware detected"                                  | `malware_detected`       |
| "suspicious login"                                  | `suspicious_login`       |

---

## 10. 🎯 Detection Rules

### Event-level rules (any number can fire on a single event)

| Rule                  | Triggers on                                                    | Severity | MITRE  |
| --------------------- | -------------------------------------------------------------- | -------- | ------ |
| `FAILED_LOGIN`        | event type `failed_login` or "failed login" in message        | HIGH     | T1110  |
| `BRUTE_FORCE`         | event type `brute_force` or "brute force" in message          | HIGH     | T1110  |
| `NETWORK_PORT_SCAN`   | "scan" in event type, or "port scan" / "network scan" in message | HIGH  | T1046  |
| `MALWARE_DETECTED`    | malware, trojan, ransomware, virus, malicious in message      | CRITICAL | T1204  |
| `UNAUTHORIZED_ACCESS` | "unauthorized" in message/status, or "intrusion" in message   | CRITICAL | T1078  |
| `EXPLOIT_ACTIVITY`    | "exploit" in message or event type                            | CRITICAL | T1190  |
| `PHISHING_ACTIVITY`   | "phishing" in message                                         | HIGH     | T1566  |
| `SUSPICIOUS_LOGIN`    | `suspicious_login`, "suspicious login" or "multiple login"    | MEDIUM   | T1078  |

### Correlation rules (look across recent events)

| Rule                | Condition                                                     | Severity | MITRE |
| ------------------- | ------------------------------------------------------------- | -------- | ----- |
| `BRUTE_FORCE`       | 5+ `failed_login` events from one IP within 5 minutes         | HIGH     | T1110 |
| `PORT_SCAN_PATTERN` | 5+ unique destination ports from one IP                       | HIGH     | T1046 |

### Severity → ticket priority

| Severity | Priority |
| -------- | -------- |
| CRITICAL | P1       |
| HIGH     | P2       |
| MEDIUM   | P3       |
| LOW      | P4       |

---

## 11. 🌐 Threat Intelligence Feed

The feed lives in `data/threat_intel.json` and is a **simulated** local file with 12 sample indicators (IPs, domains, URLs and hashes) carrying malware family, severity, confidence, risk score and MITRE techniques.

| ID      | Type   | Indicator                          | Severity | Family / Category      |
| ------- | ------ | ---------------------------------- | -------- | ---------------------- |
| TI-0001 | IP     | `185.220.101.45`                   | CRITICAL | DarkComet (C2)         |
| TI-0002 | Domain | `secure-login-check[.]com`         | HIGH     | Phishing               |
| TI-0003 | Hash   | `44d88612fea8a8f36de82e1278abb02f` | CRITICAL | AgentTesla             |
| TI-0004 | IP     | `103.216.221.17`                   | HIGH     | Brute force            |
| TI-0005 | Domain | `update-microsoft-security[.]net`  | HIGH     | SocGholish             |
| TI-0006 | Hash   | `5d41402abc4b2a76b9719d911017c592` | CRITICAL | LockBit                |
| TI-0007 | URL    | `http://login-verification[.]info/account` | HIGH | Phishing         |
| TI-0008 | IP     | `45.155.205.233`                   | MEDIUM   | Scanning               |
| TI-0009 | Domain | `cloud-storage-auth[.]org`         | HIGH     | Phishing               |
| TI-0010 | Hash   | `9e107d9d372bb6826bd81d3542a419d6` | HIGH     | Remcos                 |
| TI-0011 | IP     | `91.240.118.172`                   | HIGH     | Mirai                  |
| TI-0012 | Domain | `invoice-document-download[.]com`  | CRITICAL | QakBot                 |

**What a match does:** the alert is flagged `threat_intel_match`, gets the matched sources, malware families and ATT&CK techniques attached, and its severity is raised if the indicator's severity is higher.

**Add your own:** append an object to the `indicators` array in `data/threat_intel.json` using the same fields, then restart the app.

---

## 12. 🎫 Tickets & Reports

- **ID format:** `SOC-YYYYMMDD-00001` (counter resets daily)
- **Created automatically** for every new, non-duplicate alert
- **Default assignee:** `SOC Analyst`
- **Statuses:** `OPEN` → `IN_PROGRESS` → `RESOLVED` → `CLOSED`
- **Update status:** `PATCH /api/tickets/<id>` with `{"status": "RESOLVED"}`
- **User response / resolution notes:** the user can write their own response on any ticket. Send it in the same PATCH: `{"status": "RESOLVED", "resolution": "Blocked 185.220.101.45 on the firewall and reset the admin password."}`
  - Optional; max **10,000 characters**
  - `status` is still required in the request. The dashboard resends the ticket's current status when you only save a response
  - If `resolution` is omitted, the existing response is left unchanged; an empty string clears it
- **PDF:** `GET /api/tickets/<id>/pdf` returns an A4 report titled *SOC INCIDENT TICKET*, including the **Analyst Response / Resolution** section
- **CSV:** `GET /api/report.csv` exports all of your alerts

---

## 13. 🔌 REST API Reference

All endpoints require a logged-in session and only return **your** data. Because CSRF protection is on, state-changing requests (POST/PATCH) from outside the browser need a valid CSRF token and session cookie.

### Endpoints

| Method | Endpoint                  | Description                                   |
| ------ | ------------------------- | --------------------------------------------- |
| GET    | `/api/summary`            | `{total, critical, high, medium, open}`       |
| GET    | `/api/events`             | List events. Filters: `event_type`, `source_ip`, `status`, `username` |
| POST   | `/api/events`             | Submit an event and run the full pipeline     |
| GET    | `/api/alerts`             | List alerts. Filters: `severity`, `status`, `rule_name`, `source_ip` |
| GET    | `/api/alerts/<id>`        | One alert (404 if not yours)                  |
| GET    | `/api/iocs`               | List IOCs. Filters: `ioc_type`, `status`, `value` |
| GET    | `/api/iocs/summary`       | Counts by type                                |
| GET    | `/api/tickets`            | List tickets. Filters: `status`, `severity`, `priority`, `assignee` |
| GET    | `/api/tickets/<id>`       | One ticket                                    |
| PATCH  | `/api/tickets/<id>`       | Update ticket status and/or write the analyst response (`resolution`) |
| GET    | `/api/tickets/<id>/pdf`   | Download ticket PDF                           |
| GET    | `/api/report.csv`         | Download alerts CSV                           |

### Submit an event: request

```json
POST /api/events
{
  "event_type": "failed_login",
  "source_ip": "185.220.101.45",
  "username": "admin",
  "destination_port": 22,
  "raw_log": "Failed login for user admin"
}
```

### Response (`201 Created`, abridged, example values)

```json
{
  "event_id": 12,
  "detected": true,
  "alert_id": 7,
  "alerts": [{ "rule_name": "FAILED_LOGIN", "severity": "CRITICAL", "mitre_id": "T1110" }],
  "tickets": [{ "ticket_id": "SOC-20261008-00003", "priority": "P1" }],
  "ioc_count": 1,
  "threat_intel_match_count": 1
}
```

### Pagination

- With **no** `page`/`per_page`/filter parameters, list endpoints return a plain JSON array (backward compatible).
- With any of them, you get:

```json
{
  "items": [],
  "pagination": { "page": 1, "per_page": 25, "total": 42, "pages": 2, "has_next": true, "has_previous": false }
}
```

`page` defaults to 1; `per_page` defaults to 25 and is capped at 100.

---

## 14. 🔧 Configuration

| Variable                | Default      | Description                                              |
| ----------------------- | ------------ | -------------------------------------------------------- |
| `SECRET_KEY`            | **required** | Signs sessions/CSRF tokens. Use a long random value      |
| `FLASK_DEBUG`           | `false`      | Debug mode. **Never enable in production**               |
| `FLASK_HOST`            | `0.0.0.0`    | Bind address. Use `127.0.0.1` for local-only access      |
| `PORT`                  | `5000`       | Port to listen on                                        |
| `SESSION_COOKIE_SECURE` | `false`      | Set `true` when serving over HTTPS                       |

Fixed in code: session lifetime **1 hour**, default rate limit **200/day and 50/hour per IP**.

---

## 15. 🗄️ Database Overview

SQLite file `soc.db`, auto-created and auto-migrated at startup (new columns are added without deleting data).

| Table           | Purpose                                                          |
| --------------- | ---------------------------------------------------------------- |
| `users`         | Accounts (email lower-cased, hashed password)                    |
| `events`        | Submitted/normalized events                                      |
| `alerts`        | Alerts with severity, rule, MITRE ID and threat-intel metadata   |
| `iocs`          | Unique indicators with first/last seen and event count           |
| `ioc_events`    | Links IOCs ↔ events ↔ users                                      |
| `tickets`       | Incident tickets linked to alerts/events                         |
| `auth_failures` | Failed login attempts, used for login brute-force detection      |

To start fresh, stop the app and delete `soc.db`.

---

## 16. 📁 Project Structure

```
SentinelSOC/
├── app/
│   ├── __init__.py        # app factory, config, CSRF, rate limiter
│   ├── auth.py            # register / login / logout, login brute-force alerts
│   ├── routes.py          # page routes + REST API
│   ├── log_analyzer.py    # log normalization
│   ├── ioc_tracker.py     # IOC extraction
│   ├── threat_intel.py    # feed matching, de-fanging, severity boost
│   ├── detection.py       # detection + correlation rules, deduplication
│   ├── ticketing.py       # ticket creation + PDF export
│   └── db.py              # schema, indexes, migrations
├── data/
│   └── threat_intel.json  # simulated threat feed
├── templates/             # login, register, input, dashboard
├── tests/                 # test_detection, test_log_analyzer, test_iocs_tracker
├── run.py                 # entry point
├── requirements.txt
├── pytest.ini
├── .env.example
└── .gitignore
```

---

## 17. 🔐 Security Measures

- Passwords hashed with Werkzeug (never stored in plaintext)
- Session cookies: `HttpOnly`, `SameSite=Lax`, optional `Secure`
- Global CSRF protection (Flask-WTF)
- Rate limiting (Flask-Limiter)
- Sessions invalidated on server restart and expire after 1 hour
- Input validation for IP format, port range and required fields
- Strict per-user data isolation on every query
- `.env`, `soc.db` and `*.sqlite*` are git-ignored

---

## 18. ✅ Testing

```bash
pytest            # run everything
pytest -v         # verbose
pytest tests/test_detection.py
```

| File                    | Covers                          |
| ----------------------- | ------------------------------- |
| `test_detection.py`     | Detection rules and engine      |
| `test_iocs_tracker.py`  | IOC extraction                  |
| `test_log_analyzer.py`  | Log normalization               |

---

## 19. 🚢 Deployment

```bash
gunicorn run:app --bind 0.0.0.0:8000
```

Checklist:

- [ ] Fresh, random `SECRET_KEY`
- [ ] `FLASK_DEBUG=false`
- [ ] `SESSION_COOKIE_SECURE=true` and HTTPS in front
- [ ] Reverse proxy (nginx/Caddy) configured to forward the real client IP, otherwise rate limiting and IP logging may see only the proxy's address
- [ ] `.env` and `soc.db` **not** committed or shared
- [ ] Regular backups of `soc.db`

---

## 20. 🩹 Troubleshooting

| Problem                                               | Fix                                                                 |
| ----------------------------------------------------- | ------------------------------------------------------------------- |
| `RuntimeError: SECRET_KEY environment variable is required` | Create `.env` from `.env.example` and set `SECRET_KEY`          |
| `ModuleNotFoundError`                                 | Activate the virtualenv and run `pip install -r requirements.txt`   |
| Logged out after restarting the server                | Expected: sessions are invalidated on restart                       |
| `429 Too Many Requests`                               | Rate limit hit (50/hour, 200/day). Wait, or raise limits in `app/__init__.py` |
| Port already in use                                   | Set a different `PORT` in `.env`                                    |
| "Invalid IP" when submitting an event                 | Use a valid IPv4/IPv6 address such as `10.0.0.5`                    |
| 400 CSRF error on API POST/PATCH                      | Send the CSRF token with the request; the web UI does this for you  |
| Want to reset all data                                | Stop the app and delete `soc.db`                                    |
| No alert fired                                        | The event matched no rule; try wording such as "failed login" or "malware detected" |

---



## 📄 License

Add a license of your choice (MIT is common for portfolio projects).
