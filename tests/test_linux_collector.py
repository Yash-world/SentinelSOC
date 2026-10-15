from agents.linux_collector import classify_event, event_timestamp, extract_source_ip, extract_username


def test_classifies_ssh_failed_login_and_extracts_fields():
    line = "Oct 13 20:14:03 host sshd[123]: Failed password for invalid user testadmin from 203.0.113.77 port 22 ssh2"
    event_type, status, _ = classify_event(line, "/var/log/auth.log")
    assert event_type == "failed_login"
    assert status == "failed"
    assert extract_source_ip(line) == "203.0.113.77"
    assert extract_username(line) == "testadmin"


def test_classifies_successful_ssh_login():
    line = "Oct 13 20:14:03 host sshd[123]: Accepted publickey for deploy from 198.51.100.22 port 22 ssh2"
    assert classify_event(line)[0] == "successful_login"
    assert extract_username(line) == "deploy"


def test_classifies_sudo_command_and_audit_changes():
    sudo = "Oct 13 20:14:03 host sudo: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl http://example.invalid/x"
    assert classify_event(sudo)[0] == "sudo_command"
    assert classify_event("auditctl -e 0 disabled audit rules")[0] == "audit_policy_changed"


def test_classifies_account_and_firewall_events():
    assert classify_event("useradd[123]: new user: name=guest, UID=1002")[0] == "account_created"
    assert classify_event("[UFW BLOCK] IN=eth0 SRC=203.0.113.5 DST=192.0.2.1")[0] == "firewall_connection_blocked"


def test_timestamp_parser_handles_syslog_and_iso_prefix():
    assert event_timestamp("Oct 13 20:14:03 host sshd: Failed password")
    assert event_timestamp("2026-10-13T20:14:03Z host app: started").startswith("2026-10-13T20:14:03")
