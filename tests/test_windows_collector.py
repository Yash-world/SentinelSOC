from agents.windows_collector import classify_event, parse_event_xml


def xml_event(event_id=4625, record_id=42, data=None, channel="Security"):
    if data is None:
        data = {"TargetUserName": "test-user", "IpAddress": "203.0.113.10", "LogonType": "3"}
    data_xml = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in data.items())
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{event_id}</EventID>
      <TimeCreated SystemTime="2026-10-13T10:00:00.000Z"/><EventRecordID>{record_id}</EventRecordID>
      <Channel>{channel}</Channel><Computer>test-host</Computer></System><EventData>{data_xml}</EventData>
    </Event>'''


def test_parse_event_xml_extracts_record_id_and_fields():
    parsed = parse_event_xml(xml_event(), "Security")
    assert parsed["event_id_number"] == 4625
    assert parsed["record_id"] == 42
    assert parsed["data"]["TargetUserName"] == "test-user"
    assert parsed["channel"] == "Security"


def test_failed_logon_normalizes_for_existing_detection_rule():
    parsed = parse_event_xml(xml_event(), "Security")
    payload = classify_event(parsed, "192.0.2.20")
    assert payload["event_type"] == "failed_login"
    assert payload["status"] == "failed"
    assert payload["source_ip"] == "203.0.113.10"
    assert payload["event_id"].startswith("windows-Security-42-")
    assert "Raw Windows event XML" in payload["raw_log"]


def test_security_log_clear_maps_to_detection_type():
    parsed = parse_event_xml(xml_event(1102, 43, {}, "Security"), "Security")
    payload = classify_event(parsed, "192.0.2.20")
    assert payload["event_type"] == "security_log_cleared"
    assert payload["source_ip"] == "192.0.2.20"


def test_defender_detection_maps_to_malware_event():
    parsed = parse_event_xml(
        xml_event(1116, 5, {"Threat Name": "ExampleThreat", "Path": "C:\\Temp\\sample.exe"},
                  "Microsoft-Windows-Windows Defender/Operational"),
        "Microsoft-Windows-Windows Defender/Operational",
    )
    payload = classify_event(parsed, "192.0.2.20")
    assert payload["event_type"] == "malware_detected"
    assert "ExampleThreat" in payload["raw_log"]
