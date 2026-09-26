import hashlib
import ipaddress
import re


# -------------------------
# IOC Regex Patterns
# -------------------------

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

URL_PATTERN = re.compile(r"\bhttps?://[^\s<>'\"]+", re.IGNORECASE)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")

SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


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
# Extract IP Addresses
# -------------------------


def extract_ips(text):
    if not text:
        return []

    found = []

    for value in IP_PATTERN.findall(str(text)):
        if is_valid_ip(value):
            found.append(value)

    return sorted(set(found))


# -------------------------
# Extract Domains
# -------------------------


def extract_domains(text):
    if not text:
        return []

    found = DOMAIN_PATTERN.findall(str(text))

    return sorted(set(found))


# -------------------------
# Extract URLs
# -------------------------


def extract_urls(text):
    if not text:
        return []

    found = URL_PATTERN.findall(str(text))

    # Remove common punctuation from the end
    cleaned = []

    for url in found:
        url = url.rstrip(".,;:!?)]}")

        cleaned.append(url)

    return sorted(set(cleaned))


# -------------------------
# Extract Email Addresses
# -------------------------


def extract_emails(text):
    if not text:
        return []

    found = EMAIL_PATTERN.findall(str(text))

    return sorted(set(found))


# -------------------------
# Extract File Hashes
# -------------------------


def extract_hashes(text):
    if not text:
        return {
            "md5": [],
            "sha1": [],
            "sha256": [],
        }

    text = str(text)

    sha256 = sorted(set(SHA256_PATTERN.findall(text)))

    sha1 = sorted(set(SHA1_PATTERN.findall(text)))

    md5 = sorted(set(MD5_PATTERN.findall(text)))

    return {
        "md5": [value.lower() for value in md5],
        "sha1": [value.lower() for value in sha1],
        "sha256": [value.lower() for value in sha256],
    }


# -------------------------
# IOC Type Detection
# -------------------------


def build_ioc_list(text):
    """
    Extract all supported IOCs from text.

    Returns a list of dictionaries.
    """

    iocs = []

    for value in extract_ips(text):
        iocs.append(
            {
                "ioc_type": "ip",
                "value": value,
            }
        )

    for value in extract_domains(text):
        iocs.append(
            {
                "ioc_type": "domain",
                "value": value.lower(),
            }
        )

    for value in extract_urls(text):
        iocs.append(
            {
                "ioc_type": "url",
                "value": value,
            }
        )

    for value in extract_emails(text):
        iocs.append(
            {
                "ioc_type": "email",
                "value": value.lower(),
            }
        )

    hashes = extract_hashes(text)

    for value in hashes["md5"]:
        iocs.append(
            {
                "ioc_type": "md5",
                "value": value,
            }
        )

    for value in hashes["sha1"]:
        iocs.append(
            {
                "ioc_type": "sha1",
                "value": value,
            }
        )

    for value in hashes["sha256"]:
        iocs.append(
            {
                "ioc_type": "sha256",
                "value": value,
            }
        )

    return iocs


# -------------------------
# IOC Fingerprint
# -------------------------


def calculate_ioc_id(ioc_type, value):
    """
    Generate a stable identifier for an IOC.

    This is useful for tracking the same IOC
    across multiple security events.
    """

    raw = (f"{ioc_type}:{value.lower()}").encode("utf-8")

    return hashlib.sha256(raw).hexdigest()


# -------------------------
# Analyze Event for IOCs
# -------------------------


def extract_iocs_from_event(event):
    """
    Extract IOCs from an event.

    The original event is not modified.
    """

    event = dict(event or {})

    message = str(event.get("message", ""))

    iocs = build_ioc_list(message)

    for ioc in iocs:
        ioc["ioc_id"] = calculate_ioc_id(ioc["ioc_type"], ioc["value"])

        ioc["event_id"] = event.get("id")

        ioc["source_ip"] = event.get("source_ip")

        ioc["event_type"] = event.get("event_type")

    return {
        "event_id": event.get("id"),
        "ioc_count": len(iocs),
        "iocs": iocs,
    }


# -------------------------
# IOC Summary
# -------------------------


def summarize_iocs(iocs):
    """
    Return IOC counts grouped by type.
    """

    summary = {
        "ip": 0,
        "domain": 0,
        "url": 0,
        "email": 0,
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
    }

    for ioc in iocs or []:
        ioc_type = ioc.get("ioc_type")

        if ioc_type in summary:
            summary[ioc_type] += 1

    summary["total"] = sum(summary.values())

    return summary


# -------------------------
# Tracking Helper
# -------------------------


def track_iocs(events):
    """
    Extract and combine IOCs from multiple events.

    The same IOC is tracked as one IOC while
    keeping the number of events in which it
    appeared.
    """

    tracked = {}

    for event in events or []:
        result = extract_iocs_from_event(event)

        for ioc in result["iocs"]:
            key = (ioc["ioc_type"], ioc["value"].lower())

            if key not in tracked:
                tracked[key] = {
                    "ioc_id": ioc["ioc_id"],
                    "ioc_type": ioc["ioc_type"],
                    "value": ioc["value"],
                    "event_ids": [],
                    "event_count": 0,
                    "source_ips": [],
                }

            record = tracked[key]

            event_id = ioc.get("event_id")

            if event_id is not None and event_id not in record["event_ids"]:
                record["event_ids"].append(event_id)

            source_ip = ioc.get("source_ip")

            if source_ip and source_ip not in record["source_ips"]:
                record["source_ips"].append(source_ip)

            record["event_count"] = len(record["event_ids"])

    return list(tracked.values())
