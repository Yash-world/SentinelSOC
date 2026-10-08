
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
    source_ip = _valid_source_ip(
        event.get("source_ip")
    )

    if source_ip is None:
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
