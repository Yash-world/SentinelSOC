import ipaddress
import re
from datetime import datetime, timezone


# -------------------------
# Event Type Normalization
# -------------------------

EVENT_TYPE_MAP = {
    "failed login": "failed_login",
    "login failed": "failed_login",
    "authentication failure": "authentication_failure",
    "authentication failed": "authentication_failure",
    "auth failure": "authentication_failure",
    "invalid password": "failed_login",
    "port scan": "port_scan",
    "network scan": "network_scan",
    "port scanning": "port_scan",
    "nmap scan": "port_scan",
    "malware detected": "malware_detected",
    "virus detected": "virus",
    "trojan detected": "trojan",
    "ransomware detected": "ransomware",
    "suspicious login": "suspicious_login",
    "unusual login": "unusual_login",
    "login anomaly": "login_anomaly",
}


# -------------------------
# Regex Patterns
# -------------------------

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

PORT_PATTERN = re.compile(r"(?:port\s*[:=]?\s*|:)(\d{1,5})\b", re.IGNORECASE)

USERNAME_PATTERNS = [
    re.compile(
        r"(?:user|username|account|for)\s*[=:]?\s*([A-Za-z0-9_.@-]+)", re.IGNORECASE
    ),
]


# -------------------------
# IP Validation
# -------------------------


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


# -------------------------
# Extract IP Address
# -------------------------


def extract_ip(message):
    if not message:
        return None

    matches = IP_PATTERN.findall(message)

    for value in matches:
        if is_valid_ip(value):
            return value

    return None


# -------------------------
# Extract Port
# -------------------------


def extract_port(message):
    if not message:
        return None

    match = PORT_PATTERN.search(message)

    if not match:
        return None

    try:
        port = int(match.group(1))

        if 1 <= port <= 65535:
            return port

    except (ValueError, TypeError):
        pass

    return None


# -------------------------
# Extract Username
# -------------------------


def extract_username(message):
    if not message:
        return None

    for pattern in USERNAME_PATTERNS:
        match = pattern.search(message)

        if match:
            username = match.group(1).strip()

            if username.lower() not in {
                "authentication",
                "login",
                "failed",
                "failure",
            }:
                return username

    return None


# -------------------------
# Normalize Event Type
# -------------------------


def normalize_event_type(event_type, message):
    event_type = str(event_type or "").strip().lower()

    message_lower = str(message or "").strip().lower()

    # Direct mapping
    if event_type in EVENT_TYPE_MAP:
        return EVENT_TYPE_MAP[event_type]

    # Already normalized
    if event_type in {
        "failed_login",
        "login_failed",
        "authentication_failure",
        "auth_failure",
        "port_scan",
        "network_scan",
        "scan",
        "reconnaissance",
        "malware",
        "malware_detected",
        "virus",
        "trojan",
        "ransomware",
        "suspicious_login",
        "unusual_login",
        "login_anomaly",
    }:
        return event_type

    # Detect from message
    for keyword, normalized_type in EVENT_TYPE_MAP.items():
        if keyword in message_lower:
            return normalized_type

    return event_type or "unknown"


# -------------------------
# Log Source Detection
# -------------------------


def identify_log_source(event_type, message):
    text = (f"{event_type} {message}").lower()

    if any(
        keyword in text
        for keyword in [
            "ssh",
            "sshd",
            "failed password",
            "authentication",
            "login",
        ]
    ):
        return "authentication"

    if any(
        keyword in text
        for keyword in [
            "nmap",
            "port scan",
            "network scan",
            "destination port",
        ]
    ):
        return "network"

    if any(
        keyword in text
        for keyword in [
            "firewall",
            "blocked connection",
            "packet blocked",
        ]
    ):
        return "firewall"

    if any(
        keyword in text
        for keyword in [
            "powershell",
            "cmd.exe",
            "process",
            "endpoint",
        ]
    ):
        return "endpoint"

    if any(
        keyword in text
        for keyword in [
            "apache",
            "nginx",
            "http",
            "web request",
        ]
    ):
        return "web"

    if any(
        keyword in text
        for keyword in [
            "malware",
            "virus",
            "trojan",
            "ransomware",
        ]
    ):
        return "endpoint"

    return "unknown"


# -------------------------
# Suspicious Keyword Detection
# -------------------------

SUSPICIOUS_KEYWORDS = {
    "brute force",
    "failed login",
    "authentication failure",
    "invalid password",
    "port scan",
    "network scan",
    "nmap",
    "malware",
    "virus",
    "trojan",
    "ransomware",
    "powershell",
    "privilege escalation",
    "command execution",
    "suspicious login",
    "impossible travel",
    "malicious file",
}


def extract_suspicious_keywords(message):
    if not message:
        return []

    message_lower = message.lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in message_lower:
            found.append(keyword)

    return sorted(found)


# -------------------------
# Status Normalization
# -------------------------


def normalize_status(status, message):
    status = str(status or "").strip().lower()

    message_lower = str(message or "").lower()

    if status:
        return status

    if any(
        keyword in message_lower
        for keyword in [
            "failed",
            "failure",
            "denied",
            "blocked",
        ]
    ):
        return "failed"

    if any(
        keyword in message_lower
        for keyword in [
            "malware",
            "malicious",
            "ransomware",
            "trojan",
            "virus",
        ]
    ):
        return "malicious"

    if any(
        keyword in message_lower
        for keyword in [
            "suspicious",
            "anomaly",
            "unusual",
        ]
    ):
        return "suspicious"

    return "unknown"


# -------------------------
# Timestamp Normalization
# -------------------------


def normalize_timestamp(timestamp):
    if not timestamp:
        return datetime.now(timezone.utc).isoformat()

    timestamp = str(timestamp).strip()

    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.isoformat()

    except (ValueError, TypeError):
        return datetime.now(timezone.utc).isoformat()


# -------------------------
# Main Log Analyzer
# -------------------------


def analyze_log(event):
    """
    Normalize and enrich a raw security event.

    The original event fields are preserved.
    Additional analyzer fields are added.
    """

    event = dict(event or {})

    message = str(event.get("message", "")).strip()

    event_type = str(event.get("event_type", "")).strip()

    # Normalize basic fields
    normalized_event_type = normalize_event_type(event_type, message)

    source_ip = str(event.get("source_ip", "")).strip()

    username = str(event.get("username", "")).strip()

    # Extract missing information from message
    extracted_ip = extract_ip(message)

    if not is_valid_ip(source_ip) and extracted_ip:
        source_ip = extracted_ip

    extracted_username = extract_username(message)

    if (
        not username
        or username.lower()
        in {
            "unknown",
            "none",
            "null",
        }
    ) and extracted_username:
        username = extracted_username

    existing_port = event.get("destination_port")

    try:
        existing_port = int(existing_port)

        if not 1 <= existing_port <= 65535:
            existing_port = None

    except (ValueError, TypeError):
        existing_port = None

    extracted_port = extract_port(message)

    destination_port = existing_port if existing_port is not None else extracted_port

    normalized_status = normalize_status(event.get("status"), message)

    log_source = identify_log_source(normalized_event_type, message)

    suspicious_keywords = extract_suspicious_keywords(message)

    # Build analyzed event
    analyzed = dict(event)

    analyzed.update(
        {
            "timestamp": normalize_timestamp(event.get("timestamp")),
            "event_type": normalized_event_type,
            "source_ip": source_ip,
            "username": username,
            "destination_port": destination_port,
            "status": normalized_status,
            "message": message,
            "log_source": log_source,
            "suspicious_keywords": suspicious_keywords,
            "keyword_count": len(suspicious_keywords),
            "has_valid_ip": is_valid_ip(source_ip),
            "has_username": bool(username),
            "has_destination_port": destination_port is not None,
            "analyzer_version": "1.0",
        }
    )

    return analyzed
