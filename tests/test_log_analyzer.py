from app.log_analyzer import (
    analyze_log,
    extract_ip,
    extract_port,
    extract_username,
    normalize_event_type,
)


def test_extract_ip():
    message = "Failed login from 185.220.101.1 on SSH port 22"

    assert extract_ip(message) == "185.220.101.1"


def test_extract_port():
    message = "Connection attempt from 10.0.0.5:22"

    assert extract_port(message) == 22


def test_extract_username():
    message = "Failed login for admin from 10.0.0.5"

    assert extract_username(message) == "admin"


def test_normalize_event_type():
    result = normalize_event_type("Failed Login", "Failed password for admin")

    assert result == "failed_login"


def test_analyze_log():
    event = {
        "timestamp": "2026-09-07T19:20:00+00:00",
        "event_type": "Failed Login",
        "source_ip": "185.220.101.1",
        "username": "admin",
        "destination_port": 22,
        "status": "failed",
        "message": ("Failed login for admin from 185.220.101.1 on port 22"),
    }

    result = analyze_log(event)

    assert result["event_type"] == "failed_login"

    assert result["source_ip"] == ("185.220.101.1")

    assert result["username"] == "admin"

    assert result["destination_port"] == 22

    assert result["status"] == "failed"

    assert result["log_source"] == ("authentication")

    assert result["has_valid_ip"] is True

    assert result["has_username"] is True

    assert result["has_destination_port"] is True

    assert "failed login" in (result["suspicious_keywords"])


def test_analyzer_extracts_missing_ip():
    event = {
        "timestamp": "2026-09-07T19:20:00+00:00",
        "event_type": "failed login",
        "source_ip": "",
        "username": "admin",
        "destination_port": 22,
        "status": "failed",
        "message": ("Failed login from 10.10.10.10"),
    }

    result = analyze_log(event)

    assert result["source_ip"] == "10.10.10.10"

    assert result["has_valid_ip"] is True


def test_analyzer_extracts_missing_port():
    event = {
        "timestamp": "2026-09-07T19:20:00+00:00",
        "event_type": "network",
        "source_ip": "10.0.0.5",
        "username": "unknown",
        "destination_port": None,
        "status": "suspicious",
        "message": ("Nmap port scan detected against port 443"),
    }

    result = analyze_log(event)

    assert result["destination_port"] == 443

    assert result["event_type"] == "port_scan"

    assert result["log_source"] == "network"


def test_normal_event():
    event = {
        "timestamp": "2026-09-07T19:20:00+00:00",
        "event_type": "login",
        "source_ip": "192.168.1.20",
        "username": "user",
        "destination_port": 443,
        "status": "success",
        "message": "Successful login",
    }

    result = analyze_log(event)

    assert result["source_ip"] == "192.168.1.20"

    assert result["username"] == "user"

    assert result["destination_port"] == 443

    assert result["status"] == "success"

    assert result["has_valid_ip"] is True


WINDOWS_4625 = """An account failed to log on.

Subject:
	Security ID:		SYSTEM
	Account Name:		WIN-HOST$
	Account Domain:		WORKGROUP
	Logon ID:		0x3E7

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		NULL SID
	Account Name:		administrator
	Account Domain:		

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Network Information:
	Workstation Name:	ATTACKPC
	Source Network Address:	185.220.101.1
	Source Port:		51234
"""


def test_windows_4625_username_is_target_account_not_machine_account():
    assert extract_username(WINDOWS_4625) == "administrator"


def test_source_port_is_not_reported_as_destination_port():
    assert extract_port(WINDOWS_4625) is None
    # A real destination port in the same text must still be found.
    assert extract_port(WINDOWS_4625 + "\nDestination Port: 3389") == 3389


def test_analyze_windows_4625_end_to_end():
    result = analyze_log(
        {
            "event_type": "failed_login",
            "message": WINDOWS_4625,
            "timestamp": "2026-10-12T10:00:00Z",
        }
    )

    assert result["username"] == "administrator"
    assert result["source_ip"] == "185.220.101.1"
    assert result["destination_port"] is None
    assert result["event_type"] == "failed_login"


def test_new_windows_event_types_are_preserved():
    for event_type in ("successful_login", "privileged_logon", "account_created"):
        assert normalize_event_type(event_type, "Special privileges assigned") == event_type
