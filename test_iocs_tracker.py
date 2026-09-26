from app.ioc_tracker import (
    calculate_ioc_id,
    extract_domains,
    extract_emails,
    extract_hashes,
    extract_iocs_from_event,
    extract_ips,
    extract_urls,
    summarize_iocs,
    track_iocs,
)


def test_extract_ips():

    text = "Connection from 185.220.101.1 and 10.10.10.10"

    result = extract_ips(text)

    assert "185.220.101.1" in result
    assert "10.10.10.10" in result


def test_extract_domains():

    text = "Connection to malicious.example.com"

    result = extract_domains(text)

    assert "malicious.example.com" in result


def test_extract_urls():

    text = "User visited https://malicious.example.com/login"

    result = extract_urls(text)

    assert "https://malicious.example.com/login" in result


def test_extract_emails():

    text = "Phishing email from attacker@example.com"

    result = extract_emails(text)

    assert "attacker@example.com" in result


def test_extract_hashes():

    md5 = "d41d8cd98f00b204e9800998ecf8427e"

    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    text = f"{md5} {sha1} {sha256}"

    result = extract_hashes(text)

    assert md5 in result["md5"]

    assert sha1 in result["sha1"]

    assert sha256 in result["sha256"]


def test_build_iocs_from_event():

    event = {
        "id": 10,
        "event_type": "malware",
        "source_ip": "10.0.0.5",
        "message": (
            "Malware downloaded from "
            "https://evil.example.com/payload "
            "using 185.220.101.1"
        ),
    }

    result = extract_iocs_from_event(event)

    assert result["event_id"] == 10

    assert result["ioc_count"] >= 3

    types = {ioc["ioc_type"] for ioc in result["iocs"]}

    assert "ip" in types
    assert "url" in types
    assert "domain" in types


def test_ioc_id_is_stable():

    first = calculate_ioc_id("ip", "185.220.101.1")

    second = calculate_ioc_id("ip", "185.220.101.1")

    assert first == second


def test_summarize_iocs():

    iocs = [
        {
            "ioc_type": "ip",
            "value": "10.0.0.1",
        },
        {
            "ioc_type": "ip",
            "value": "10.0.0.2",
        },
        {
            "ioc_type": "domain",
            "value": "evil.example.com",
        },
    ]

    result = summarize_iocs(iocs)

    assert result["ip"] == 2

    assert result["domain"] == 1

    assert result["total"] == 3


def test_track_iocs():

    events = [
        {
            "id": 1,
            "event_type": "failed_login",
            "source_ip": "10.0.0.5",
            "message": ("Failed login from 185.220.101.1"),
        },
        {
            "id": 2,
            "event_type": "suspicious_login",
            "source_ip": "10.0.0.6",
            "message": ("Connection from 185.220.101.1"),
        },
    ]

    result = track_iocs(events)

    matching = [
        item
        for item in result
        if item["ioc_type"] == "ip" and item["value"] == "185.220.101.1"
    ]

    assert len(matching) == 1

    assert matching[0]["event_count"] == 2

    assert set(matching[0]["event_ids"]) == {1, 2}
