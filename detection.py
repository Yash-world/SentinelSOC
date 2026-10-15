
from datetime import datetime, timezone, timedelta
import copy
import hashlib
import ipaddress
import json

from .db import get_db
from .ticketing import create_ticket
from .threat_intel import boost_severity


# =========================================================
# Detection Rules
# =========================================================

def _valid_source_ip(source_ip):
    """
    Validate and return a usable source IP.
    """
    if not source_ip:
        return None

    try:
        ipaddress.ip_address(str(source_ip))
    except ValueError:
        return None

    return str(source_ip)


def _base_alert(
    severity,
    rule_name,
    title,
    description,
    source_ip,
    mitre_id,
):
    """
    Build a normalized alert dictionary.
    """
    return {
        "severity": severity,
        "rule_name": rule_name,
        "title": title,
        "description": description,
        "source_ip": source_ip,
        "mitre_id": mitre_id,
        "status": "OPEN",
    }


# =========================================================
# Individual Detection Rules
# =========================================================

def _rule_failed_login(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {"failed_login", "login_failed", "authentication_failure", "auth_failure"}:
        return _base_alert(
            "HIGH",
            "FAILED_LOGIN",
            "Failed Login Detected",
            "A failed authentication attempt was detected.",
            event.get("source_ip"),
            "T1110",
        )

    return None


def _rule_brute_force_event(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {"brute_force", "brute_force_login"}:
        return _base_alert(
            "HIGH",
            "BRUTE_FORCE",
            "Brute Force Activity Detected",
            "Multiple failed login attempts indicate possible brute-force activity.",
            event.get("source_ip"),
            "T1110",
        )

    return None


def _rule_port_scan(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {"port_scan", "network_scan", "scan", "reconnaissance"}:
        return _base_alert(
            "HIGH",
            "NETWORK_PORT_SCAN",
            "Possible Port Scan Detected",
            "Network scanning activity was detected.",
            event.get("source_ip"),
            "T1046",
        )

    return None


def _rule_malware(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {
        "malware",
        "malware_detected",
        "virus",
        "trojan",
        "ransomware",
    }:
        return _base_alert(
            "CRITICAL",
            "MALWARE_DETECTED",
            "Malware Activity Detected",
            "Potential malware-related activity was detected in the security event.",
            event.get("source_ip"),
            "T1204",
        )

    return None


def _rule_unauthorized_access(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    status = str(
        event.get("status", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {
        "unauthorized_access",
        "unauthorized",
        "intrusion",
    } or status in {"unauthorized", "intrusion"}:
        return _base_alert(
            "CRITICAL",
            "UNAUTHORIZED_ACCESS",
            "Unauthorized Access Detected",
            "Possible unauthorized access or intrusion activity was detected.",
            event.get("source_ip"),
            "T1078",
        )

    return None


def _rule_exploit(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {
        "exploit",
        "exploit_activity",
    }:
        return _base_alert(
            "CRITICAL",
            "EXPLOIT_ACTIVITY",
            "Possible Exploitation Activity",
            "Potential exploitation activity was detected.",
            event.get("source_ip"),
            "T1190",
        )

    return None


def _rule_phishing(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {"phishing", "phishing_activity"}:
        return _base_alert(
            "HIGH",
            "PHISHING_ACTIVITY",
            "Possible Phishing Activity",
            "Potential phishing-related activity was detected.",
            event.get("source_ip"),
            "T1566",
        )

    return None


def _rule_suspicious_login(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    message = str(
        event.get("message", "")
    ).strip().lower()

    if event_type in {
        "suspicious_login",
        "unusual_login",
        "login_anomaly",
    }:
        return _base_alert(
            "MEDIUM",
            "SUSPICIOUS_LOGIN",
            "Suspicious Login Activity Detected",
            "Suspicious login activity was detected from the source.",
            event.get("source_ip"),
            "T1078",
        )

    return None


def _rule_account_created(event):
    event_type = str(
        event.get("event_type", "")
    ).strip().lower()

    if event_type == "account_created":
        username = str(event.get("username") or "unknown")

        return _base_alert(
            "MEDIUM",
            "NEW_ACCOUNT_CREATED",
            "New Local Account Created",
            f"A new user account ({username}) was created on the host.",
            event.get("source_ip"),
            "T1136",
        )

    return None


# Windows-specific rules emitted by agents/windows_collector.py.
def _rule_windows_security_changes(event):
    if str(event.get("platform", "")).strip().lower() == "linux":
        return None
    event_type = str(event.get("event_type", "")).strip().lower()
    message = str(event.get("message", "")).lower()
    rules = {
        "security_log_cleared": ("CRITICAL", "WINDOWS_SECURITY_LOG_CLEARED", "Windows Security Log Cleared", "T1070.001"),
        "audit_policy_changed": ("HIGH", "WINDOWS_AUDIT_POLICY_CHANGED", "Windows Audit Policy Changed", "T1562.002"),
        "service_installed": ("HIGH", "WINDOWS_SERVICE_INSTALLED", "Windows Service Installed", "T1543.003"),
        "scheduled_task_created": ("MEDIUM", "WINDOWS_SCHEDULED_TASK_CREATED", "Scheduled Task Created", "T1053.005"),
        "account_enabled": ("MEDIUM", "WINDOWS_ACCOUNT_ENABLED", "Windows Account Enabled", "T1098"),
        "account_disabled": ("MEDIUM", "WINDOWS_ACCOUNT_DISABLED", "Windows Account Disabled", "T1098"),
        "account_deleted": ("MEDIUM", "WINDOWS_ACCOUNT_DELETED", "Windows Account Deleted", "T1531"),
        "defender_configuration_changed": ("HIGH", "DEFENDER_CONFIGURATION_CHANGED", "Microsoft Defender Configuration Changed", "T1562.001"),
        "attack_surface_reduction_blocked": ("HIGH", "DEFENDER_ASR_BLOCKED", "Defender Blocked Suspicious Activity", "T1059"),
        "firewall_connection_blocked": ("LOW", "WINDOWS_FIREWALL_BLOCKED_CONNECTION", "Windows Firewall Blocked a Connection", "T1562.004"),
    }
    spec = rules.get(event_type)
    if not spec:
        return None
    severity, rule_name, title, mitre_id = spec
    description = f"Windows event telemetry indicates: {event_type.replace('_', ' ')}. Review the attached event evidence and confirm whether the change was authorized."
    if event_type == "security_log_cleared":
        description = "The Windows Security audit log was cleared. This may be legitimate maintenance or an attempt to remove forensic evidence."
    elif event_type == "audit_policy_changed":
        description = "The Windows audit policy changed. Verify the change was authorized and that required security auditing remains enabled."
    elif event_type == "service_installed":
        description = "A Windows service was installed. Verify the service name, binary path, signer and change ticket."
    elif event_type == "defender_configuration_changed":
        description = "Microsoft Defender configuration changed. Verify tamper protection and security controls were not weakened."
    return _base_alert(severity, rule_name, title, description, event.get("source_ip"), mitre_id)


def _rule_windows_malware(event):
    event_type = str(event.get("event_type", "")).strip().lower()
    # malware_detected is already handled by the generic _rule_malware rule.
    if event_type != "malware_remediated":
        return None
    return _base_alert(
        "HIGH", "WINDOWS_DEFENDER_REMEDIATION",
        "Microsoft Defender Threat Remediation",
        "Microsoft Defender reported taking action on a threat. Review the threat name, affected path, remediation status and endpoint before closing the alert.",
        event.get("source_ip"), "T1204",
    )


def _rule_suspicious_process_creation(event):
    if str(event.get("platform", "")).strip().lower() == "linux":
        return None
    if str(event.get("event_type", "")).strip().lower() != "process_created":
        return None
    message = str(event.get("message", "")).lower()
    suspicious_markers = (
        "-encodedcommand", "-enc ", "frombase64string", "downloadstring(",
        "invoke-expression", " iwr ", "http://", "https://", "\\appdata\\",
        "\\temp\\", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
    )
    if not any(marker in message for marker in suspicious_markers):
        return None
    return _base_alert(
        "HIGH", "WINDOWS_SUSPICIOUS_PROCESS", "Potentially Suspicious Process Execution",
        "Process creation telemetry contains a command or path commonly worth investigating. This is heuristic and may be a false positive; validate the full command line and parent process.",
        event.get("source_ip"), "T1059",
    )


def _rule_linux_security_events(event):
    """Detection rules for normalized Linux authentication and host telemetry."""
    if str(event.get("platform", "")).strip().lower() == "windows":
        return None
    event_type = str(event.get("event_type", "")).strip().lower()
    message = str(event.get("message", "")).strip().lower()
    rules = {
        "account_deleted": ("MEDIUM", "LINUX_ACCOUNT_DELETED", "Linux Account Deleted", "T1531",
                            "A local Linux account deletion was recorded. Confirm it was authorized."),
        "account_modified": ("MEDIUM", "LINUX_ACCOUNT_MODIFIED", "Linux Account or Group Modified", "T1098",
                              "A local account or group change was recorded. Verify privileged group membership."),
        "ssh_key_added": ("HIGH", "LINUX_SSH_KEY_ACTIVITY", "SSH Authorized Keys Changed", "T1098.004",
                           "Activity involving an SSH authorized_keys file was observed. Verify the key and account owner."),
        "service_installed": ("HIGH", "LINUX_SERVICE_INSTALLED", "Linux Service Installed or Enabled", "T1543.002",
                              "A service installation or enablement was observed. Verify the unit file and executable path."),
        "scheduled_task_created": ("MEDIUM", "LINUX_SCHEDULED_TASK_ACTIVITY", "Cron or Scheduled Task Activity", "T1053.003",
                                    "Cron or scheduled-task activity was observed. Verify the job and its owner."),
        "firewall_rule_changed": ("HIGH", "LINUX_FIREWALL_RULE_CHANGED", "Linux Firewall Rules Changed", "T1562.004",
                                  "A firewall configuration change was observed. Verify the change was approved."),
        "audit_policy_changed": ("HIGH", "LINUX_AUDIT_POLICY_CHANGED", "Linux Audit Policy Changed", "T1562.012",
                                 "Linux audit configuration may have changed. Verify auditd and required rules remain enabled."),
        "security_log_cleared": ("CRITICAL", "LINUX_SECURITY_LOG_CLEARED", "Possible Linux Security Log Removal", "T1070.002",
                                 "Log-clearing or journal-vacuum activity was observed. Investigate possible evidence removal."),
        "privilege_escalation": ("HIGH", "LINUX_PRIVILEGE_ESCALATION", "Linux Root Session Opened", "T1068",
                                 "A root session was opened. Confirm the user, source and administrative reason."),
        "kernel_module_loaded": ("MEDIUM", "LINUX_KERNEL_MODULE_LOADED", "Linux Kernel Module Loaded", "T1547",
                                 "Kernel module loading activity was recorded. Verify the module origin and signature."),
        "malware_detected": ("CRITICAL", "LINUX_MALWARE_DETECTED", "Linux Malware Detection Reported", "T1204",
                             "A security tool reported a possible malware finding. Review the file, detection name and remediation status."),
        "unauthorized_access": ("MEDIUM", "LINUX_ACCESS_DENIED", "Linux Access-Control Denial", "T1222",
                                "An access-control denial was recorded. Check whether it indicates attempted unauthorized access."),
        "firewall_connection_blocked": ("LOW", "LINUX_FIREWALL_BLOCKED_CONNECTION", "Linux Firewall Blocked a Connection", "T1562.004",
                                        "Linux firewall telemetry reports blocked traffic. Review the source and destination if the activity is unexpected."),
    }
    spec = rules.get(event_type)
    if spec is not None:
        severity, rule_name, title, mitre_id, description = spec
        return _base_alert(severity, rule_name, title, description, event.get("source_ip"), mitre_id)

    if event_type == "sudo_command":
        risky = ("useradd", "usermod", "visudo", "chmod 777", "curl", "wget", "bash -c", "sh -c",
                 "base64 -d", "iptables", "nft ", "systemctl disable", "auditctl -e 0", "rm -rf")
        if any(marker in message for marker in risky):
            return _base_alert(
                "HIGH", "LINUX_SUSPICIOUS_SUDO_COMMAND", "Potentially Risky Sudo Command",
                "A privileged command contains a high-risk administrative or download/execution pattern. Validate command intent and the initiating user.",
                event.get("source_ip"), "T1059",
            )

    if event_type == "process_created":
        suspicious = ("curl ", "wget ", "base64 -d", "chmod +x", " /tmp/", " /dev/shm/",
                      "python -c", "perl -e", "nc -e", "ncat -e", "bash -i", "socat ",
                      "iptables -f", "auditctl -e 0", "rm -f /var/log", "history -c")
        if any(marker in message for marker in suspicious):
            return _base_alert(
                "HIGH", "LINUX_SUSPICIOUS_PROCESS", "Potentially Suspicious Linux Process",
                "Process/audit telemetry contains a command pattern worth investigating. This heuristic can produce false positives; review full command, parent process and user.",
                event.get("source_ip"), "T1059",
            )
    return None


# =========================================================
# Rule Registry
# =========================================================

DETECTION_RULES = [
    _rule_failed_login,
    _rule_brute_force_event,
    _rule_port_scan,
    _rule_malware,
    _rule_unauthorized_access,
    _rule_exploit,
    _rule_phishing,
    _rule_suspicious_login,
    _rule_account_created,
    _rule_windows_security_changes,
    _rule_windows_malware,
    _rule_suspicious_process_creation,
    _rule_linux_security_events,
]


# =========================================================
# Multiple Rule Detection
# =========================================================

def detect_event_rules(event):
    """
    Run ALL detection rules against one event.

    Returns:
        list[dict]

    This is the new multiple-rule detection API.
    """
    if not isinstance(event, dict):
        return []

    # IMPORTANT: the explicitly selected event_type is authoritative.
    # A log message containing words such as "failed login", "malicious",
    # or "malware" must NOT create unrelated alerts when the user selected
    # another event type (for example, port_scan).
    raw_source_ip = str(event.get("source_ip") or "").strip()
    source_ip = _valid_source_ip(raw_source_ip)

    # Host-local events (account changes, log clearing, service installs) often
    # have no remote source IP. Permit a missing IP but continue rejecting an
    # explicitly malformed one.
    if raw_source_ip and source_ip is None:
        return []

    normalized_event = dict(event)
    normalized_event["source_ip"] = source_ip

    alerts = []

    for rule in DETECTION_RULES:
        try:
            alert = rule(normalized_event)
        except (TypeError, ValueError, KeyError):
            alert = None

        if alert is None:
            continue

        alert["source_ip"] = source_ip
        alerts.append(alert)

    return alerts


# =========================================================
# Backward-Compatible Single Detection API
# =========================================================

def detect_event(event):
    """
    Analyze a single security event.

    Returns:
        dict | None

    This keeps compatibility with the existing tests and
    existing code that expects:

        alert["rule_name"]

    For multiple rule matches use:

        detect_event_rules(event)
    """
    alerts = detect_event_rules(event)

    if not alerts:
        return None

    return alerts[0]


# =========================================================
# Timestamp Helper
# =========================================================

def _parse_timestamp(timestamp):
    """
    Convert ISO timestamp into timezone-aware UTC datetime.
    """
    if not timestamp:
        return None

    try:
        parsed_timestamp = datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )

        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(
                tzinfo=timezone.utc
            )

        return parsed_timestamp.astimezone(
            timezone.utc
        )

    except (ValueError, TypeError):
        return None


# =========================================================
# Brute Force Correlation
# =========================================================

def detect_brute_force(events):
    """
    Detect five or more failed login attempts from the same
    source IP within five minutes.
    """
    grouped_events = {}

    for event in events or []:
        if not isinstance(event, dict):
            continue

        event_type = str(
            event.get("event_type", "")
        ).strip().lower()

        if event_type != "failed_login":
            continue

        source_ip = _valid_source_ip(
            event.get("source_ip")
        )

        if source_ip is None:
            continue

        parsed_timestamp = _parse_timestamp(
            event.get("timestamp")
        )

        if parsed_timestamp is None:
            continue

        grouped_events.setdefault(
            source_ip,
            []
        ).append(parsed_timestamp)

    alerts = []

    for source_ip, timestamps in grouped_events.items():
        timestamps.sort()

        for index, start_time in enumerate(timestamps):
            end_time = (
                start_time
                + timedelta(minutes=5)
            )

            attempts = [
                timestamp
                for timestamp in timestamps[index:]
                if timestamp <= end_time
            ]

            if len(attempts) >= 5:
                alerts.append(
                    _base_alert(
                        "HIGH",
                        "BRUTE_FORCE",
                        "Brute Force Activity Detected",
                        (
                            "Multiple failed login attempts "
                            f"were detected from {source_ip} "
                            "within five minutes."
                        ),
                        source_ip,
                        "T1110",
                    )
                )
                break

    return alerts


# =========================================================
# Successful Login After Repeated Failures
# =========================================================

def detect_success_after_failures(
    events,
    min_failures=5,
    window_minutes=10,
):
    """
    Detect a successful login from the same source IP that follows
    ``min_failures`` or more failed logins within ``window_minutes``.

    A brute-force run that ends in a success usually means the account
    is compromised, so this is raised as CRITICAL.
    """
    failures = {}
    successes = {}

    for event in events or []:
        if not isinstance(event, dict):
            continue

        event_type = str(
            event.get("event_type", "")
        ).strip().lower()

        if event_type not in {"failed_login", "successful_login"}:
            continue

        source_ip = _valid_source_ip(
            event.get("source_ip")
        )

        if source_ip is None:
            continue

        parsed_timestamp = _parse_timestamp(
            event.get("timestamp")
        )

        if parsed_timestamp is None:
            continue

        target = (
            failures
            if event_type == "failed_login"
            else successes
        )

        target.setdefault(
            source_ip,
            [],
        ).append(parsed_timestamp)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for source_ip, success_times in successes.items():
        failure_times = failures.get(source_ip, [])

        for success_time in sorted(success_times):
            preceding = [
                timestamp
                for timestamp in failure_times
                if success_time - window <= timestamp <= success_time
            ]

            if len(preceding) >= min_failures:
                alerts.append(
                    _base_alert(
                        "CRITICAL",
                        "SUCCESS_AFTER_BRUTE_FORCE",
                        "Successful Login After Repeated Failures",
                        (
                            f"A successful login from {source_ip} followed "
                            f"{len(preceding)} failed attempts within "
                            f"{window_minutes} minutes. The account may be "
                            "compromised."
                        ),
                        source_ip,
                        "T1110",
                    )
                )
                break

    return alerts


# =========================================================
# Port Scan Correlation
# =========================================================

def detect_port_scan(events):
    """
    Detect five or more unique destination ports scanned
    from the same source IP.
    """
    grouped_ports = {}

    for event in events or []:
        if not isinstance(event, dict):
            continue

        event_type = str(
            event.get("event_type", "")
        ).strip().lower()

        if event_type != "port_scan":
            continue

        source_ip = _valid_source_ip(
            event.get("source_ip")
        )

        if source_ip is None:
            continue

        destination_port = event.get(
            "destination_port"
        )

        if destination_port is None:
            continue

        try:
            destination_port = int(
                destination_port
            )
        except (TypeError, ValueError):
            continue

        if not 1 <= destination_port <= 65535:
            continue

        grouped_ports.setdefault(
            source_ip,
            set()
        ).add(destination_port)

    alerts = []

    for source_ip, ports in grouped_ports.items():
        if len(ports) >= 5:
            alerts.append(
                _base_alert(
                    "HIGH",
                    "PORT_SCAN_PATTERN",
                    "Port Scan Pattern Detected",
                    (
                        "Multiple destination ports were "
                        f"scanned from {source_ip}."
                    ),
                    source_ip,
                    "T1046",
                )
            )

    return alerts


# =========================================================
# Alert Fingerprint
# =========================================================

DEDUP_WINDOW_MINUTES = 5


def _normalize_fingerprint_value(value):
    """
    Normalize values used for alert fingerprinting.
    """
    if value is None:
        return ""

    if isinstance(value, (list, tuple, set)):
        return ",".join(
            sorted(
                str(item).strip().lower()
                for item in value
                if item is not None
            )
        )

    if isinstance(value, dict):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        )

    return str(value).strip().lower()


def build_alert_fingerprint(
    alert,
    event,
    user_id,
):
    """
    Build deterministic alert fingerprint.

    Correlation alerts:
        user + rule + source

    Event alerts:
        user + rule + source + event characteristics
    """
    rule_name = _normalize_fingerprint_value(
        alert.get("rule_name")
    )

    source_ip = _normalize_fingerprint_value(
        alert.get("source_ip")
    )

    user_value = _normalize_fingerprint_value(
        user_id
    )

    correlation_rules = {
        "BRUTE_FORCE",
        "PORT_SCAN_PATTERN",
    }

    if rule_name in correlation_rules:
        raw_value = "|".join(
            [
                user_value,
                rule_name,
                source_ip,
            ]
        )
    else:
        raw_value = "|".join(
            [
                user_value,
                rule_name,
                source_ip,
                _normalize_fingerprint_value(
                    event.get("event_type")
                ),
                _normalize_fingerprint_value(
                    event.get("username")
                ),
                _normalize_fingerprint_value(
                    event.get("destination_port")
                ),
                _normalize_fingerprint_value(
                    event.get("message")
                ),
            ]
        )

    return hashlib.sha256(
        raw_value.encode("utf-8")
    ).hexdigest()


# =========================================================
# Duplicate Alert Check
# =========================================================

def _find_duplicate_alert(
    alert,
    user_id,
    fingerprint,
    event=None,
):
    """
    Find an equivalent alert created recently.

    Uses the existing alerts schema, so no database migration
    is required for this version.
    """
    event = event or {}

    db = get_db()

    rule_name = alert.get(
        "rule_name"
    )

    source_ip = alert.get(
        "source_ip"
    )

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(
            minutes=DEDUP_WINDOW_MINUTES
        )
    ).isoformat()

    rows = db.execute(
        """
        SELECT
            id,
            created_at,
            rule_name,
            source_ip,
            title,
            description
        FROM alerts
        WHERE user_id = ?
          AND rule_name = ?
          AND (
                source_ip = ?
                OR (
                    source_ip IS NULL
                    AND ? IS NULL
                )
              )
          AND created_at >= ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (
            user_id,
            rule_name,
            source_ip,
            source_ip,
            cutoff,
        ),
    ).fetchall()

    current_content = "|".join(
        [
            _normalize_fingerprint_value(
                user_id
            ),
            _normalize_fingerprint_value(
                alert.get("rule_name")
            ),
            _normalize_fingerprint_value(
                alert.get("source_ip")
            ),
            _normalize_fingerprint_value(
                alert.get("title")
            ),
            _normalize_fingerprint_value(
                alert.get("description")
            ),
        ]
    )

    current_content_hash = hashlib.sha256(
        current_content.encode("utf-8")
    ).hexdigest()

    for row in rows:
        if rule_name in {
            "BRUTE_FORCE",
            "PORT_SCAN_PATTERN",
        }:
            existing_base = "|".join(
                [
                    _normalize_fingerprint_value(
                        user_id
                    ),
                    _normalize_fingerprint_value(
                        row["rule_name"]
                    ),
                    _normalize_fingerprint_value(
                        row["source_ip"]
                    ),
                ]
            )

            existing_hash = hashlib.sha256(
                existing_base.encode("utf-8")
            ).hexdigest()

            if existing_hash == fingerprint:
                return row["id"]

        existing_content = "|".join(
            [
                _normalize_fingerprint_value(
                    user_id
                ),
                _normalize_fingerprint_value(
                    row["rule_name"]
                ),
                _normalize_fingerprint_value(
                    row["source_ip"]
                ),
                _normalize_fingerprint_value(
                    row["title"]
                ),
                _normalize_fingerprint_value(
                    row["description"]
                ),
            ]
        )

        existing_content_hash = hashlib.sha256(
            existing_content.encode("utf-8")
        ).hexdigest()

        if (
            existing_content_hash
            == current_content_hash
        ):
            return row["id"]

    return None


# =========================================================
# Save Alert
# =========================================================

def save_alert(
    alert,
    user_id,
    event=None,
):
    """
    Save alert if it is not already present.

    Returns:
        alert_id
    """
    event = event or {}

    fingerprint = build_alert_fingerprint(
        alert,
        event,
        user_id,
    )

    duplicate_id = _find_duplicate_alert(
        alert,
        user_id,
        fingerprint,
        event,
    )

    if duplicate_id is not None:
        return duplicate_id

    db = get_db()

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
            status,
            threat_intel_match,
            threat_intel_source,
            malware_family,
            mitre_attack
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            user_id,
            datetime.now(
                timezone.utc
            ).isoformat(),
            alert["severity"],
            alert["rule_name"],
            alert["title"],
            alert["description"],
            alert.get("source_ip"),
            alert.get("mitre_id"),
            alert.get(
                "status",
                "OPEN",
            ),
            1 if alert.get(
                "threat_intel_match",
                False,
            ) else 0,
            json.dumps(
                alert.get(
                    "threat_intel_source",
                    [],
                )
            ),
            json.dumps(
                alert.get(
                    "malware_family",
                    [],
                )
            ),
            json.dumps(
                alert.get(
                    "mitre_attack",
                    [],
                )
            ),
        ),
    )

    db.commit()

    return cursor.lastrowid


# =========================================================
# Threat Intelligence Enrichment
# =========================================================

def enrich_alert(
    alert,
    threat_intel_matches,
):
    """
    Add threat-intelligence information to an alert.
    """
    alert = copy.deepcopy(alert)

    threat_intel_matches = (
        threat_intel_matches or []
    )

    alert["threat_intel_match"] = False
    alert["threat_intel_matches"] = []
    alert["threat_intel_source"] = []
    alert["malware_family"] = []
    alert["mitre_attack"] = []

    if not threat_intel_matches:
        return alert

    alert["threat_intel_match"] = True
    alert["threat_intel_matches"] = (
        threat_intel_matches
    )

    alert["severity"] = boost_severity(
        alert.get("severity"),
        threat_intel_matches,
    )

    sources = []
    malware_families = []
    mitre_attack = []

    for match in threat_intel_matches:
        if not isinstance(match, dict):
            continue

        intel = match.get(
            "threat_intel",
            {},
        )

        if not isinstance(intel, dict):
            continue

        source = intel.get("source")

        if source:
            if isinstance(source, list):
                for item in source:
                    if (
                        item
                        and item not in sources
                    ):
                        sources.append(item)
            elif source not in sources:
                sources.append(source)

        intel_sources = intel.get(
            "sources",
            [],
        )

        if isinstance(
            intel_sources,
            list,
        ):
            for item in intel_sources:
                if (
                    item
                    and item not in sources
                ):
                    sources.append(item)

        malware_family = intel.get(
            "malware_family"
        )

        if malware_family:
            if isinstance(
                malware_family,
                list,
            ):
                for family in malware_family:
                    if (
                        family
                        and family not in malware_families
                    ):
                        malware_families.append(
                            family
                        )
            elif malware_family not in malware_families:
                malware_families.append(
                    malware_family
                )

        mitre_values = intel.get(
            "mitre_attack",
            [],
        )

        if isinstance(
            mitre_values,
            str,
        ):
            mitre_values = [
                mitre_values
            ]

        if isinstance(
            mitre_values,
            list,
        ):
            for technique in mitre_values:
                if (
                    technique
                    and technique not in mitre_attack
                ):
                    mitre_attack.append(
                        technique
                    )

    alert["threat_intel_source"] = sources
    alert["malware_family"] = (
        malware_families
    )
    alert["mitre_attack"] = (
        mitre_attack
    )

    return alert


# =========================================================
# Process Event
# =========================================================

def process_event(
    event,
    user_id,
    threat_intel_matches=None,
):
    """
    Process an event through:

        1. Rule-based detection
        2. Correlation
        3. Deduplication
        4. Threat-intelligence enrichment
        5. Alert storage
        6. SOC ticket creation

    Multiple rules can generate multiple alerts.
    """

    # =====================================================
    # 1. Run ALL event-level rules
    # =====================================================

    alerts = detect_event_rules(
        event
    )

    # =====================================================
    # 2. Get recent events for correlation
    # =====================================================

    db = get_db()

    recent_events = db.execute(
        """
        SELECT
            timestamp,
            event_type,
            source_ip,
            username,
            destination_port,
            status,
            message
        FROM events
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 100
        """,
        (user_id,),
    ).fetchall()

    event_history = [
        dict(row)
        for row in recent_events
    ]

    # =====================================================
    # 3. Brute Force Correlation
    # =====================================================

    alerts.extend(
        detect_brute_force(
            event_history
        )
    )

    # =====================================================
    # 4. Port Scan Correlation
    # =====================================================

    alerts.extend(
        detect_port_scan(
            event_history
        )
    )

    # =====================================================
    # 4b. Success-after-failures Correlation
    # =====================================================

    alerts.extend(
        detect_success_after_failures(
            event_history
        )
    )

    # =====================================================
    # 5. Remove duplicate rule matches
    # =====================================================

    unique_alerts = []
    seen_rules = set()

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        key = (
            alert.get("rule_name"),
            alert.get("source_ip"),
        )

        if key in seen_rules:
            continue

        seen_rules.add(key)
        unique_alerts.append(alert)

    alerts = unique_alerts

    # =====================================================
    # 6. No Detection
    # =====================================================

    if not alerts:
        return {
            "detected": False,
            "alert_id": None,
            "alert": None,
            "ticket": None,
            "alert_ids": [],
            "alerts": [],
            "tickets": [],
        }

    # =====================================================
    # 7. Threat Intelligence
    # =====================================================

    threat_intel_matches = (
        threat_intel_matches or []
    )

    alerts = [
        enrich_alert(
            alert,
            threat_intel_matches,
        )
        for alert in alerts
    ]

    # =====================================================
    # 8. Save alerts + tickets
    # =====================================================

    saved_alerts = []
    alert_ids = []
    tickets = []

    for alert in alerts:
        fingerprint = build_alert_fingerprint(
            alert,
            event,
            user_id,
        )

        duplicate_id = _find_duplicate_alert(
            alert,
            user_id,
            fingerprint,
            event,
        )

        is_duplicate = (
            duplicate_id is not None
        )

        if is_duplicate:
            alert_id = duplicate_id
        else:
            alert_id = save_alert(
                alert,
                user_id,
                event,
            )

        alert_ids.append(
            alert_id
        )

        ticket = None

        if not is_duplicate:
            try:
                ticket = create_ticket(
                    alert=alert,
                    event_id=event.get("id"),
                    alert_id=alert_id,
                    user_id=user_id,
                )
            except (
                TypeError,
                ValueError,
                KeyError,
            ):
                ticket = None

        if ticket is not None:
            tickets.append(ticket)

        saved_alert = copy.deepcopy(
            alert
        )

        saved_alert["alert_id"] = alert_id
        saved_alert["deduplicated"] = (
            is_duplicate
        )

        saved_alerts.append(
            saved_alert
        )

    # =====================================================
    # 9. Backward Compatibility
    # =====================================================

    primary_alert = saved_alerts[0]
    primary_alert_id = alert_ids[0]

    primary_ticket = (
        tickets[0]
        if tickets
        else None
    )

    return {
        "detected": True,

        # Existing API fields
        "alert_id": primary_alert_id,
        "alert": primary_alert,
        "ticket": primary_ticket,

        # New multiple-alert fields
        "alert_ids": alert_ids,
        "alerts": saved_alerts,
        "tickets": tickets,
    }
