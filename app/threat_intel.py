import json
import os


# =========================================================
# THREAT INTELLIGENCE FILE
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

THREAT_INTEL_FILE = os.path.join(
    BASE_DIR,
    "data",
    "threat_intel.json"
)


# =========================================================
# SEVERITY RANKING
# =========================================================

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# =========================================================
# NORMALIZE IOC VALUE
# =========================================================

def normalize_ioc_value(value):
    """
    Normalize IOC values.

    Examples:

        secure-login-check[.]com
        secure-login-check.com

    are treated as the same IOC.
    """

    if value is None:
        return ""

    value = str(value).strip().lower()

    # Defanged IOC format
    value = value.replace("[.]", ".")

    # Other common defanging formats
    value = value.replace("(.)", ".")
    value = value.replace("[dot]", ".")

    return value


# =========================================================
# LOAD THREAT INTELLIGENCE
# =========================================================

def load_threat_intel():
    """
    Load indicators from:

        data/threat_intel.json

    Expected structure:

        {
            "indicators": [
                {...},
                {...}
            ]
        }
    """

    if not os.path.exists(THREAT_INTEL_FILE):
        return []

    try:
        with open(
            THREAT_INTEL_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, dict):
        return []

    indicators = data.get("indicators", [])

    if not isinstance(indicators, list):
        return []

    return indicators


# =========================================================
# CHECK IOC TYPE
# =========================================================

def indicator_type_matches(ioc_type, indicator):
    """
    Match extracted IOC type against
    threat-intelligence IOC type.

    Supported:

        ip
        domain
        url
        md5
        sha1
        sha256
    """

    if not isinstance(indicator, dict):
        return False

    ti_type = str(
        indicator.get("type", "")
    ).strip().lower()

    indicator_type = str(
        indicator.get("indicator_type", "")
    ).strip().lower()

    ioc_type = str(
        ioc_type or ""
    ).strip().lower()

    # -----------------------------------------------------
    # IP
    # -----------------------------------------------------

    if ioc_type == "ip":
        return ti_type == "ip"

    # -----------------------------------------------------
    # DOMAIN
    # -----------------------------------------------------

    if ioc_type == "domain":
        return ti_type == "domain"

    # -----------------------------------------------------
    # URL
    # -----------------------------------------------------

    if ioc_type == "url":
        return ti_type == "url"

    # -----------------------------------------------------
    # HASH
    # -----------------------------------------------------

    if ioc_type in {
        "md5",
        "sha1",
        "sha256"
    }:

        if ti_type != "hash":
            return False

        return indicator_type == ioc_type

    return False


# =========================================================
# LOOKUP ONE IOC
# =========================================================

def lookup_ioc(ioc_type, value):
    """
    Search one IOC against threat_intel.json.

    Returns the matching threat-intelligence
    record or None.
    """

    normalized_value = normalize_ioc_value(value)

    if not normalized_value:
        return None

    indicators = load_threat_intel()

    for indicator in indicators:

        if not indicator_type_matches(
            ioc_type,
            indicator
        ):
            continue

        intel_value = normalize_ioc_value(
            indicator.get("value")
        )

        if intel_value == normalized_value:
            return indicator

    return None


# =========================================================
# ENRICH EXTRACTED IOCs
# =========================================================

def enrich_iocs(iocs):
    """
    Check every extracted IOC against
    the local threat-intelligence database.

    Returns:

        [
            {
                "ioc_type": "ip",
                "value": "1.2.3.4",
                "threat_intel": {
                    ...
                }
            }
        ]
    """

    matches = []

    for ioc in iocs or []:

        if not isinstance(ioc, dict):
            continue

        ioc_type = ioc.get("ioc_type")
        value = ioc.get("value")

        if not ioc_type or not value:
            continue

        match = lookup_ioc(
            ioc_type,
            value
        )

        if match:

            matches.append({
                "ioc_type": ioc_type,
                "value": value,
                "threat_intel": match
            })

    return matches


# =========================================================
# CALCULATE ENRICHED SEVERITY
# =========================================================

def boost_severity(current_severity, matches):
    """
    Boost alert severity based on the highest
    threat-intelligence severity.

    Examples:

        MEDIUM + HIGH
            -> HIGH

        HIGH + CRITICAL
            -> CRITICAL

        CRITICAL + LOW
            -> CRITICAL
    """

    current = str(
        current_severity or "LOW"
    ).strip().upper()

    current_rank = SEVERITY_RANK.get(
        current,
        1
    )

    highest = current

    for match in matches or []:

        if not isinstance(match, dict):
            continue

        intel = match.get(
            "threat_intel",
            {}
        )

        if not isinstance(intel, dict):
            continue

        intel_severity = str(
            intel.get("severity", "")
        ).strip().upper()

        intel_rank = SEVERITY_RANK.get(
            intel_severity,
            0
        )

        if intel_rank > current_rank:

            current_rank = intel_rank
            highest = intel_severity

    return highest


# =========================================================
# GET THREAT INTEL SOURCES
# =========================================================

def get_sources(matches):
    """
    Extract unique threat-intelligence sources
    from matched indicators.
    """

    sources = []

    for match in matches or []:

        intel = match.get(
            "threat_intel",
            {}
        )

        if not isinstance(intel, dict):
            continue

        source = intel.get("source")

        if source:
            if source not in sources:
                sources.append(source)

        multiple_sources = intel.get("sources")

        if isinstance(multiple_sources, list):

            for item in multiple_sources:

                if item and item not in sources:
                    sources.append(item)

        elif multiple_sources:

            if multiple_sources not in sources:
                sources.append(
                    str(multiple_sources)
                )

    return sources


# =========================================================
# GET MALWARE FAMILIES
# =========================================================

def get_malware_families(matches):
    """
    Extract unique malware-family names
    from matched indicators.
    """

    families = []

    for match in matches or []:

        intel = match.get(
            "threat_intel",
            {}
        )

        if not isinstance(intel, dict):
            continue

        malware_family = intel.get(
            "malware_family"
        )

        if isinstance(malware_family, list):

            for family in malware_family:

                if family and family not in families:
                    families.append(family)

        elif malware_family:

            malware_family = str(
                malware_family
            )

            if malware_family not in families:
                families.append(malware_family)

    return families


# =========================================================
# GET MITRE ATT&CK TECHNIQUES
# =========================================================

def get_mitre_attack(matches):
    """
    Extract unique MITRE ATT&CK techniques
    from matched indicators.

    Supports:

        mitre_attack
        mitre_id
    """

    techniques = []

    for match in matches or []:

        intel = match.get(
            "threat_intel",
            {}
        )

        if not isinstance(intel, dict):
            continue

        value = intel.get("mitre_attack")

        if value is None:
            value = intel.get("mitre_id")

        if isinstance(value, list):

            for technique in value:

                if technique and technique not in techniques:
                    techniques.append(technique)

        elif value:

            value = str(value)

            if value not in techniques:
                techniques.append(value)

    return techniques
