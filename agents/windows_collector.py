#!/usr/bin/env python3
"""SentinelSOC Windows Event Log collector (no PowerShell).

Collects selected Windows Security, System, and Microsoft Defender events using
Windows Event Log APIs via pywin32. Sends normalized JSON events to SentinelSOC.
Run only on Windows systems you own or are explicitly authorized to monitor.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_URL = os.environ.get("SENTINELSOC_URL", "").rstrip("/")
SOURCE_ID = os.environ.get("SENTINELSOC_SOURCE_ID", "")
TOKEN = os.environ.get("SENTINELSOC_TOKEN", "")
HISTORY_DAYS = max(0, int(os.environ.get("SENTINELSOC_HISTORY_DAYS", "7")))
POLL_SECONDS = max(2.0, float(os.environ.get("SENTINELSOC_POLL_SECONDS", "5")))
MIN_SEND_INTERVAL = max(0.55, float(os.environ.get("SENTINELSOC_SEND_INTERVAL", "0.62")))

# Event IDs are grouped by channel. Firewall allowed-connection event 5156 is
# intentionally excluded by default because it can be extremely high-volume.
DEFAULT_EVENTS = {
    "Security": [4624, 4625, 4672, 4688, 4697, 4698, 4699, 4719, 4720, 4722, 4725, 4726, 1102, 5157],
    "System": [6008, 7036, 7045],
    "Microsoft-Windows-Windows Defender/Operational": [1116, 1117, 1121, 5007],
}


def configured_events() -> dict[str, list[int]]:
    raw = os.environ.get("SENTINELSOC_EVENT_IDS", "").strip()
    if not raw:
        return DEFAULT_EVENTS
    try:
        requested = {int(part) for part in raw.replace(";", ",").split(",") if part.strip()}
    except ValueError as exc:
        raise SystemExit("SENTINELSOC_EVENT_IDS must be comma-separated numeric event IDs.") from exc
    result = {channel: [event_id for event_id in ids if event_id in requested]
              for channel, ids in DEFAULT_EVENTS.items()}
    result = {channel: ids for channel, ids in result.items() if ids}
    if not result:
        supported = sorted({event_id for ids in DEFAULT_EVENTS.values() for event_id in ids})
        raise SystemExit(f"No supported IDs selected. Supported IDs: {','.join(map(str, supported))}")
    return result


def get_host_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("192.0.2.1", 9))  # TEST-NET address; no application data is sent.
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return "127.0.0.1"


def checkpoint_path() -> Path:
    configured = os.environ.get("SENTINELSOC_STATE_FILE", "").strip()
    if configured:
        return Path(configured).expanduser()
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SentinelSOC"
    return base / f"windows-source-{SOURCE_ID or 'source'}.json"


def load_state(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(state, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def parse_event_xml(xml_text: str, channel: str) -> dict:
    root = ET.fromstring(xml_text)
    system = root.find("{*}System")
    if system is None:
        raise ValueError("Windows event XML has no System node")
    event_id_node = system.find("{*}EventID")
    record_node = system.find("{*}EventRecordID")
    time_node = system.find("{*}TimeCreated")
    provider_node = system.find("{*}Provider")
    computer_node = system.find("{*}Computer")
    event_id = int(event_id_node.text or "0") if event_id_node is not None else 0
    record_id = int(record_node.text or "0") if record_node is not None else 0
    timestamp = time_node.attrib.get("SystemTime") if time_node is not None else None
    data = {}
    for node in root.findall(".//{*}EventData/{*}Data"):
        name = node.attrib.get("Name")
        if name:
            data[name] = node.text or ""
    # Some providers use UserData rather than EventData. Keep XML text as evidence.
    provider = provider_node.attrib.get("Name", "") if provider_node is not None else ""
    computer = computer_node.text if computer_node is not None else socket.gethostname()
    return {"event_id_number": event_id, "record_id": record_id, "timestamp": timestamp,
            "data": data, "provider": provider, "computer": computer, "channel": channel,
            "xml": xml_text}


def classify_event(event: dict, host_ip: str) -> dict:
    event_id = event["event_id_number"]
    data = event["data"]
    channel = event["channel"]
    username = (data.get("TargetUserName") or data.get("SubjectUserName") or
                data.get("AccountName") or data.get("User") or "")
    remote_ip = data.get("IpAddress") or data.get("ClientAddress") or data.get("SourceAddress") or ""
    if remote_ip in {"-", "::1", "127.0.0.1", ""}:
        remote_ip = host_ip
    status = ""
    event_type = "windows_event"
    summary = f"Windows event {event_id} from {event.get('provider', 'unknown provider')}"
    mapping = {
        4625: ("failed_login", "failed", "Failed Windows logon"),
        4624: ("successful_login", "success", "Successful Windows logon"),
        4672: ("privileged_logon", "success", "Special privileges assigned to logon"),
        4688: ("process_created", "success", "A new process was created"),
        4697: ("service_installed", "success", "A service was installed"),
        4698: ("scheduled_task_created", "success", "A scheduled task was created"),
        4699: ("scheduled_task_deleted", "success", "A scheduled task was deleted"),
        4719: ("audit_policy_changed", "success", "System audit policy changed"),
        4720: ("account_created", "success", "A user account was created"),
        4722: ("account_enabled", "success", "A user account was enabled"),
        4725: ("account_disabled", "success", "A user account was disabled"),
        4726: ("account_deleted", "success", "A user account was deleted"),
        1102: ("security_log_cleared", "success", "The Windows Security audit log was cleared"),
        5157: ("firewall_connection_blocked", "blocked", "Windows Filtering Platform blocked a connection"),
        6008: ("unexpected_shutdown", "warning", "The previous system shutdown was unexpected"),
        7036: ("service_state_changed", "info", "A Windows service changed state"),
        7045: ("service_installed", "success", "A new Windows service was installed"),
        1116: ("malware_detected", "detected", "Microsoft Defender detected malware or a potentially unwanted application"),
        1117: ("malware_remediated", "remediated", "Microsoft Defender took action on a threat"),
        1121: ("attack_surface_reduction_blocked", "blocked", "Microsoft Defender attack surface reduction rule blocked an action"),
        5007: ("defender_configuration_changed", "changed", "Microsoft Defender configuration changed"),
    }
    if event_id in mapping:
        event_type, status, summary = mapping[event_id]
    if event_id == 4625:
        username = data.get("TargetUserName", username)
    elif event_id in (4720, 4722, 4725, 4726):
        username = data.get("TargetUserName", username)
    elif event_id == 4688:
        username = data.get("SubjectUserName", username)
        summary += f"; process={data.get('NewProcessName', 'unknown')} parent={data.get('ParentProcessName', 'unknown')}"
    elif event_id in (4697, 7045):
        summary += f"; service={data.get('ServiceName', 'unknown')} image={data.get('ImagePath', data.get('ServiceFileName', 'unknown'))}"
    elif event_id == 4698:
        summary += f"; task={data.get('TaskName', 'unknown')}"
    elif event_id in (1116, 1117):
        summary += f"; threat={data.get('Threat Name', data.get('ThreatName', 'unknown'))} path={data.get('Path', 'unknown')}"
    elif event_id == 5157:
        remote_ip = data.get("DestAddress") or data.get("SourceAddress") or remote_ip
        summary += f"; app={data.get('Application', 'unknown')} destination={data.get('DestAddress', 'unknown')} port={data.get('DestPort', 'unknown')}"
    if not username:
        username = ""
    timestamp = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        timestamp = parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        timestamp = datetime.now(timezone.utc).isoformat()
    evidence = (summary + "\n" + json.dumps(data, ensure_ascii=False, sort_keys=True) +
                "\n\nRaw Windows event XML:\n" + event["xml"])
    evidence = evidence[:15000]
    event_key = hashlib.sha256(f"{event['channel']}:{event['record_id']}:{event_id}".encode()).hexdigest()
    return {
        "event_id": f"windows-{event['channel'].replace('/', '_')}-{event['record_id']}-{event_id}",
        "platform": "windows",
        "event_type": event_type, "status": status, "username": username[:128],
        "source_ip": remote_ip[:64], "timestamp": timestamp, "raw_log": evidence,
        "provider": event.get("provider", ""), "computer": event.get("computer", ""),
        "channel": channel, "event_id_number": event_id, "record_id": event["record_id"],
        "event_key": event_key,
    }


def send_event(payload: dict) -> None:
    body = {key: payload[key] for key in ("event_id", "platform", "event_type", "status", "username", "source_ip", "timestamp", "raw_log")}
    request = urllib.request.Request(
        f"{BASE_URL}/api/ingest/{SOURCE_ID}", data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    while True:
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response.read()
            time.sleep(MIN_SEND_INTERVAL)
            return
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise SystemExit(f"Connector token rejected (HTTP {exc.code}); verify source ID and token.") from exc
            if exc.code == 429 or exc.code >= 500:
                print(f"Server returned HTTP {exc.code}; retrying in 5 seconds.", file=sys.stderr)
                time.sleep(5)
                continue
            # Permanent rejection: do not silently mark as sent; make operator aware.
            raise RuntimeError(f"Server rejected event (HTTP {exc.code}): {exc.read()[:500]!r}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"Network send failed; retrying in 5 seconds: {exc}", file=sys.stderr)
            time.sleep(5)


def main() -> int:
    if os.name != "nt":
        raise SystemExit("This collector runs on Windows only.")
    parsed_url = urlparse(BASE_URL)
    if not BASE_URL or not SOURCE_ID.isdigit() or not TOKEN:
        raise SystemExit("Set SENTINELSOC_URL, SENTINELSOC_SOURCE_ID and SENTINELSOC_TOKEN first.")
    if parsed_url.scheme != "https" and parsed_url.hostname not in {"localhost", "127.0.0.1"}:
        raise SystemExit("Use HTTPS for remote SentinelSOC URLs.")
    try:
        import win32evtlog  # provided by pywin32
    except ImportError as exc:
        raise SystemExit("Missing pywin32. Install with: python -m pip install -r requirements-windows.txt") from exc

    selected = configured_events()
    state_file = checkpoint_path()
    state = load_state(state_file)
    host_ip = get_host_ip()
    history_cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)
    if HISTORY_DAYS == 0:
        # Live-only mode: mark each channel's current newest record before polling.
        reverse_flag = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        for channel in selected:
            if channel in state:
                continue
            try:
                newest_query = win32evtlog.EvtQuery(channel, reverse_flag, "*")
                newest_batch = win32evtlog.EvtNext(newest_query, 1, 1000, 0)
                if newest_batch:
                    try:
                        newest_xml = win32evtlog.EvtRender(newest_batch[0], win32evtlog.EvtRenderEventXml)
                        state[channel] = parse_event_xml(newest_xml, channel)["record_id"]
                    finally:
                        win32evtlog.EvtClose(newest_batch[0])
                else:
                    state[channel] = 0
                win32evtlog.EvtClose(newest_query)
            except Exception as exc:
                print(f"Could not initialize live-only checkpoint for '{channel}': {exc}", file=sys.stderr)
        save_state(state_file, state)
    print(f"SentinelSOC Python Windows collector started for {socket.gethostname()} ({host_ip}).")
    print(f"Channels: {', '.join(selected)}; historical backfill: {HISTORY_DAYS} day(s).")
    print(f"Checkpoint: {state_file}. Stop with Ctrl+C.")

    # Windows Event Log API functions are part of pywin32. Query each channel
    # independently because EventRecordID values are channel-local.
    flags = win32evtlog.EvtQueryChannelPath
    last_send = 0.0
    while True:
        made_progress = False
        for channel, event_ids in selected.items():
            last_record = int(state.get(channel, 0) or 0)
            id_expr = " or ".join(f"EventID={event_id}" for event_id in event_ids)
            if last_record > 0:
                xpath = f"*[System[({id_expr}) and (EventRecordID > {last_record})]]"
            else:
                # First start: restrict backfill to recent history.
                millis = HISTORY_DAYS * 24 * 60 * 60 * 1000
                xpath = f"*[System[({id_expr}) and TimeCreated[timediff(@SystemTime) <= {millis}]]]" if HISTORY_DAYS else f"*[System[({id_expr}) and (EventRecordID > 0)]]"
            try:
                query = win32evtlog.EvtQuery(channel, flags, xpath)
                while True:
                    batch = win32evtlog.EvtNext(query, 32, 1000, 0)
                    if not batch:
                        break
                    for handle in batch:
                        try:
                            xml_text = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                            parsed = parse_event_xml(xml_text, channel)
                            record_id = parsed["record_id"]
                            if record_id <= int(state.get(channel, 0) or 0):
                                continue
                            if parsed.get("timestamp"):
                                try:
                                    event_dt = datetime.fromisoformat(parsed["timestamp"].replace("Z", "+00:00"))
                                    if event_dt.tzinfo is None:
                                        event_dt = event_dt.replace(tzinfo=timezone.utc)
                                    if HISTORY_DAYS and not state.get(channel) and event_dt < history_cutoff:
                                        state[channel] = max(int(state.get(channel, 0) or 0), record_id)
                                        save_state(state_file, state)
                                        continue
                                except ValueError:
                                    pass
                            payload = classify_event(parsed, host_ip)
                            delay = MIN_SEND_INTERVAL - (time.monotonic() - last_send)
                            if delay > 0:
                                time.sleep(delay)
                            send_event(payload)
                            last_send = time.monotonic()
                            state[channel] = record_id
                            save_state(state_file, state)
                            made_progress = True
                            print(f"Sent {channel} EventID={parsed['event_id_number']} RecordID={record_id} type={payload['event_type']}")
                        finally:
                            win32evtlog.EvtClose(handle)
                win32evtlog.EvtClose(query)
            except Exception as exc:
                # A missing optional channel or access denied must be visible, not silently ignored.
                print(f"Could not read channel '{channel}': {exc}", file=sys.stderr)
                if channel == "Security":
                    print("Check that the agent has permission to read the Security log and that auditing is enabled.", file=sys.stderr)
        if not made_progress:
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Collector stopped by user.")
        raise SystemExit(0)
