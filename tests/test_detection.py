from app.detection import (
    detect_event,
    detect_brute_force,
    detect_port_scan,
)


def test_failed_login_detection():
    event = {
        "event_type": "failed_login",
        "source_ip": "192.168.1.10",
        "username": "admin",
        "destination_port": 22,
        "status": "failed",
        "message": "Failed login attempt",
    }

    alert = detect_event(event)

    assert alert is not None
    assert alert["rule_name"] == "FAILED_LOGIN"
    assert alert["severity"] == "HIGH"
    assert alert["mitre_id"] == "T1110"


def test_port_scan_detection():
    event = {
        "event_type": "port_scan",
        "source_ip": "10.0.0.5",
        "username": "unknown",
        "destination_port": 22,
        "status": "suspicious",
        "message": "Nmap port scan detected",
    }

    alert = detect_event(event)

    assert alert is not None
    assert alert["rule_name"] == "NETWORK_PORT_SCAN"
    assert alert["severity"] == "HIGH"
    assert alert["mitre_id"] == "T1046"


def test_malware_detection():
    event = {
        "event_type": "malware",
        "source_ip": "10.0.0.20",
        "username": "user",
        "destination_port": 443,
        "status": "malicious",
        "message": "Malware detected",
    }

    alert = detect_event(event)

    assert alert is not None
    assert alert["rule_name"] == "MALWARE_DETECTED"
    assert alert["severity"] == "CRITICAL"


def test_suspicious_login_detection():
    event = {
        "event_type": "suspicious_login",
        "source_ip": "172.16.0.15",
        "username": "admin",
        "destination_port": 443,
        "status": "success",
        "message": "Suspicious login detected",
    }

    alert = detect_event(event)

    assert alert is not None
    assert alert["rule_name"] == "SUSPICIOUS_LOGIN"
    assert alert["severity"] == "MEDIUM"
    assert alert["mitre_id"] == "T1078"


def test_invalid_ip_is_ignored():
    event = {
        "event_type": "failed_login",
        "source_ip": "invalid-ip",
        "username": "admin",
        "destination_port": 22,
        "status": "failed",
        "message": "Failed login attempt",
    }

    alert = detect_event(event)

    assert alert is None


def test_normal_event_has_no_alert():
    event = {
        "event_type": "login",
        "source_ip": "192.168.1.50",
        "username": "user",
        "destination_port": 443,
        "status": "success",
        "message": "Normal successful login",
    }

    alert = detect_event(event)

    assert alert is None


def test_brute_force_detection():
    events = []

    for i in range(5):
        events.append(
            {
                "event_type": "failed_login",
                "source_ip": "192.168.1.100",
                "username": "admin",
                "destination_port": 22,
                "status": "failed",
                "message": "Failed login attempt",
                "timestamp": f"2026-09-03T10:0{i}:00+00:00",
            }
        )

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "BRUTE_FORCE"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mitre_id"] == "T1110"


def test_port_scan_pattern_detection():
    events = []

    for port in [21, 22, 23, 80, 443]:
        events.append(
            {
                "event_type": "port_scan",
                "source_ip": "10.10.10.10",
                "username": "unknown",
                "destination_port": port,
                "status": "suspicious",
                "message": "Port scan",
                "timestamp": "2026-09-03T10:00:00+00:00",
            }
        )

    alerts = detect_port_scan(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "PORT_SCAN_PATTERN"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mitre_id"] == "T1046"
