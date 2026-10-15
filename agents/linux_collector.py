#!/usr/bin/env python3
"""SentinelSOC Linux security-log collector.

Collects supported Linux security/system logs, classifies common security events,
extracts useful fields, and forwards them to SentinelSOC over HTTPS. By default it
backfills readable log files and then follows new lines. Set
SENTINELSOC_START_MODE=live to start at each file's current end.

Use only on hosts you own or are authorized to monitor. Access to some logs requires
root or membership in the relevant system log/audit groups. Audit rules and services
must be enabled on the host for their events to exist.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

URL = os.environ.get("SENTINELSOC_URL", "").rstrip("/")
SOURCE_ID = os.environ.get("SENTINELSOC_SOURCE_ID", "")
TOKEN = os.environ.get("SENTINELSOC_TOKEN", "")
POLL_SECONDS = max(0.2, float(os.environ.get("SENTINELSOC_POLL_SECONDS", "1")))
START_MODE = os.environ.get("SENTINELSOC_START_MODE", "hybrid").strip().lower()
MIN_SEND_INTERVAL = max(0.55, float(os.environ.get("SENTINELSOC_SEND_INTERVAL", "0.62")))
MAX_MESSAGE_CHARS = 15000

DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",       # Debian/Ubuntu authentication
    "/var/log/secure",         # RHEL/Fedora authentication
    "/var/log/syslog",         # Debian/Ubuntu general system log
    "/var/log/messages",       # RHEL-family general system log
    "/var/log/audit/audit.log",# auditd records
    "/var/log/ufw.log",        # UFW firewall (when configured to file)
    "/var/log/fail2ban.log",   # fail2ban (when configured to file)
    "/var/log/kern.log",       # kernel messages
    "/var/log/cron",           # cron on some distributions
]

IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
USER_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?([\w.@+-]+) from ", re.I),
    re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for ([\w.@+-]+) from ", re.I),
    re.compile(r"Invalid user ([\w.@+-]+) from ", re.I),
    re.compile(r"(?:useradd|new user)[: ]+['\"]?([\w.@+-]+)", re.I),
    re.compile(r"(?:userdel|delete user)[: ]+['\"]?([\w.@+-]+)", re.I),
    re.compile(r"sudo:\s*([\w.@+-]+)\s*:", re.I),
]


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip("[](),;")))
    except ValueError:
        return None


def extract_source_ip(line: str) -> str | None:
    for match in IPV4_RE.finditer(line):
        valid = _valid_ip(match.group(0))
        if valid:
            return valid
    for match in IPV6_RE.finditer(line):
        valid = _valid_ip(match.group(0))
        if valid and not ipaddress.ip_address(valid).is_loopback:
            return valid
    return None


def extract_username(line: str) -> str | None:
    for pattern in USER_PATTERNS:
        match = pattern.search(line)
        if match:
            name = match.group(1).strip("'\" ,;:")
            if name and name.lower() not in {"unknown", "invalid", "root"}:
                return name[:128]
            if name.lower() == "root":
                return name
    return None


def classify_event(line: str, path: str = "") -> tuple[str, str, str]:
    """Return (event_type, status, concise rule reason) from common Linux log text."""
    text = line.lower()
    log_path = path.lower()

    if any(x in text for x in ("failed password", "authentication failure", "failed publickey", "maximum authentication attempts exceeded", "invalid user")):
        return "failed_login", "failed", "Linux authentication failure"
    if any(x in text for x in ("accepted password", "accepted publickey", "accepted keyboard-interactive")):
        return "successful_login", "success", "Linux authentication success"
    if "fail2ban" in text and any(x in text for x in (" banned ", "ban ", "found ")):
        return "brute_force", "blocked", "Fail2ban reported a source being blocked"
    if "sudo:" in text and "command=" in text:
        return "sudo_command", "success", "Sudo command execution"
    if re.search(r"pam_unix\(su(?:-l)?:session\): session opened for user root", text) or re.search(r"\bsu\[\d+\].*session opened for user root", text):
        return "privilege_escalation", "success", "Root shell/session opened"
    if any(x in text for x in ("new user:", "useradd[", " useradd ", "created user", "new account")):
        return "account_created", "success", "Local account creation record"
    if any(x in text for x in ("userdel[", " deleted user", "delete user", "removed user")):
        return "account_deleted", "success", "Local account deletion record"
    if any(x in text for x in ("usermod[", "changed user", "group added", "gpasswd")):
        return "account_modified", "success", "Local account or group modification"
    if "authorized_keys" in text and any(x in text for x in ("create", "write", "modified", "type=path", "opened")):
        return "ssh_key_added", "success", "SSH authorized_keys file activity"
    if any(x in text for x in ("ufw block", "[ufw block]", "blocked connection")) or re.search(r"(?:iptables|ip6tables|nftables?).*(?:drop|reject)", text):
        return "firewall_connection_blocked", "blocked", "Firewall blocked traffic"
    if any(x in text for x in ("iptables", "ip6tables", "nft add rule", "firewall-cmd --add", "ufw allow", "ufw deny", "ufw delete")):
        return "firewall_rule_changed", "changed", "Firewall configuration command or change"
    if any(x in text for x in ("auditctl -e", "enabled=0")) or re.search(r"auditd.*disabled|audit system.*disabled|audit rules.*changed", text):
        return "audit_policy_changed", "changed", "Linux audit configuration change"
    if any(x in text for x in ("systemd-journald.*vacuum", "journalctl --vacuum", "audit.log.*truncat", "log file.*cleared", "logs were cleared")):
        return "security_log_cleared", "changed", "Potential security log removal"
    if any(x in text for x in ("created symlink /etc/systemd/system", "installed .* service", "new unit file", "systemd.*enabled", "service installed")):
        return "service_installed", "success", "Service installation or enablement"
    if any(x in text for x in ("crontab", "/etc/cron.", "/var/spool/cron", "cron job added", "scheduled task")):
        return "scheduled_task_created", "changed", "Cron or scheduled-task activity"
    if any(x in text for x in ("apt install", "apt-get install", "dpkg:.* install", "installed: ", "dnf install", "yum install", "pacman -s")):
        return "package_installed", "success", "Software package installation record"
    if any(x in text for x in ("insmod ", "modprobe ", "module loaded", "loading kernel module", "inserted module")):
        return "kernel_module_loaded", "success", "Kernel module loading activity"
    if any(x in text for x in ("malware detected", "virus detected", "threat detected", "quarantined malware")) or re.search(r"clam(?:av|d).*found", text):
        return "malware_detected", "detected", "Antivirus or security tool reported a threat"
    if any(x in text for x in ("type=execve", "type=syscall", "comm=\"bash\"", "process started", "execve(")):
        return "process_created", "observed", "Process execution/audit telemetry"
    if any(x in text for x in ("permission denied", "apparmor=\"denied\"", "avc: denied", "selinux.*denied")):
        return "unauthorized_access", "denied", "Linux access-control denial"
    return "unknown", "observed", "Unclassified Linux log event"


def event_timestamp(line: str) -> str:
    """Parse ISO-8601 or classic syslog timestamp; otherwise use receive time."""
    text = line.strip()
    iso_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)", text)
    candidate = iso_match.group(1).replace("Z", "+00:00") if iso_match else ""
    try:
        parsed = datetime.fromisoformat(candidate)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass
    try:
        now = datetime.now().astimezone()
        parsed = datetime.strptime(f"{now.year} {text[:15]}", "%Y %b %d %H:%M:%S").replace(tzinfo=now.tzinfo)
        if parsed > now:
            parsed = parsed.replace(year=parsed.year - 1)
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).isoformat()


def save_state(state_path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
    temp = state_path + ".tmp"
    with open(temp, "w", encoding="utf-8") as out:
        json.dump(state, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, state_path)


def send_line(line: bytes, path: str, inode: int, offset: int, state_path: str, state: dict) -> str:
    clean = line.decode("utf-8", errors="replace").rstrip("\r\n")
    if not clean.strip():
        return "skip"
    event_id_hash = hashlib.sha256(f"{path}:{inode}:{offset}:{clean}".encode("utf-8", errors="replace")).hexdigest()
    event_type, status, reason = classify_event(clean, path)
    payload = {
        "event_id": f"linux-{event_id_hash}",
        "platform": "linux",
        "event_type": event_type,
        "status": status,
        "source_ip": extract_source_ip(clean) or "",
        "username": extract_username(clean) or "",
        "timestamp": event_timestamp(clean),
        "message": clean[:MAX_MESSAGE_CHARS],
        "raw_log": clean[:MAX_MESSAGE_CHARS],
        "metadata": {"platform": "linux", "log_path": path, "classification_reason": reason},
    }
    request = urllib.request.Request(
        f"{URL}/api/ingest/{SOURCE_ID}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    while True:
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                response.read()
            time.sleep(MIN_SEND_INTERVAL)
            return "sent"
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise SystemExit(f"Collector token rejected (HTTP {exc.code}); verify source ID/token and connector status.") from exc
            if exc.code == 429 or exc.code >= 500:
                print(f"Server returned HTTP {exc.code}; retrying in 5 seconds.", file=sys.stderr)
                time.sleep(5)
                continue
            # Preserve rejected evidence locally before advancing, to avoid silent loss.
            rejected = state_path + ".rejected.jsonl"
            with open(rejected, "a", encoding="utf-8") as out:
                out.write(json.dumps({"path": path, "offset": offset, "http_status": exc.code, "payload": payload}, ensure_ascii=False) + "\n")
            print(f"Server rejected line (HTTP {exc.code}); saved to {rejected}: {exc}", file=sys.stderr)
            return "skip"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"Send failed; retrying in 5 seconds: {exc}", file=sys.stderr)
            time.sleep(5)


@dataclass
class Tail:
    path: str
    handle: object
    inode: int
    offset: int


def discover_paths() -> list[str]:
    configured = os.environ.get("SENTINELSOC_LOG_PATHS", "").strip()
    if configured:
        return list(dict.fromkeys(os.path.abspath(p.strip()) for p in configured.split(os.pathsep) if p.strip()))
    cli_paths = sys.argv[1:]
    if cli_paths:
        return list(dict.fromkeys(os.path.abspath(p) for p in cli_paths))
    return [p for p in DEFAULT_LOG_PATHS if os.path.isfile(p)]



def run_journal(state_path: str) -> int:
    """Follow systemd journal JSON records, resuming by journal cursor."""
    if not shutil.which("journalctl"):
        raise SystemExit("journalctl was requested but is not installed or not on PATH.")
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}
    cursor = state.get("_journal_cursor")
    command = ["journalctl", "--follow", "--output=json", "--no-pager"]
    if cursor:
        command.append(f"--after-cursor={cursor}")
        print("Resuming systemd journal after saved cursor.")
    else:
        days = os.environ.get("SENTINELSOC_HISTORY_DAYS", "7")
        if not days.isdigit():
            raise SystemExit("SENTINELSOC_HISTORY_DAYS must be a non-negative integer.")
        if int(days) > 0:
            command.extend(["--since", f"{days} days ago"])
        print(f"Starting systemd journal collection (history: {days} day(s)).")
    print("Following systemd journal; Ctrl+C to stop.")
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1)
    except OSError as exc:
        raise SystemExit(f"Could not start journalctl: {exc}") from exc
    try:
        assert process.stdout is not None
        for raw in process.stdout:
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                print(f"journalctl output: {raw.rstrip()}", file=sys.stderr)
                continue
            message = str(record.get("MESSAGE", "")).replace("\x00", "")
            if not message.strip():
                continue
            realtime = record.get("__REALTIME_TIMESTAMP")
            try:
                stamp = datetime.fromtimestamp(int(realtime) / 1_000_000, timezone.utc).isoformat()
            except (TypeError, ValueError, OSError):
                stamp = datetime.now(timezone.utc).isoformat()
            identifier = str(record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or "journal")
            host = str(record.get("_HOSTNAME") or "localhost")
            line = f"{stamp} {host} {identifier}: {message}"
            current_cursor = record.get("__CURSOR")
            if not current_cursor:
                print("Skipping journal record without __CURSOR.", file=sys.stderr)
                continue
            pseudo_offset = int(hashlib.sha256(str(current_cursor).encode()).hexdigest()[:15], 16)
            result = send_line(line.encode("utf-8"), "systemd-journal", 0, pseudo_offset, state_path, state)
            if result in {"sent", "skip"}:
                state["_journal_cursor"] = current_cursor
                save_state(state_path, state)
        code = process.wait()
        if code:
            print(f"journalctl exited with status {code}; check journal permissions and journal retention.", file=sys.stderr)
        return code
    except KeyboardInterrupt:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        print("Stopping systemd journal collector.")
        return 0
    finally:
        if process.poll() is None:
            process.terminate()


def main() -> int:
    parsed_url = urlparse(URL)
    if parsed_url.scheme != "https" and parsed_url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("Use HTTPS for remote SentinelSOC URLs.")
    if not SOURCE_ID.isdigit() or not TOKEN or not URL:
        raise SystemExit("Set SENTINELSOC_URL, SENTINELSOC_SOURCE_ID and SENTINELSOC_TOKEN.")
    if START_MODE not in {"hybrid", "live"}:
        raise SystemExit("SENTINELSOC_START_MODE must be 'hybrid' or 'live'.")
    state_path = os.environ.get("SENTINELSOC_STATE_FILE", os.path.expanduser(f"~/.sentinelsoc-{SOURCE_ID}-checkpoint.json"))
    if os.environ.get("SENTINELSOC_USE_JOURNAL", "0").strip().lower() in {"1", "true", "yes"}:
        return run_journal(state_path)
    paths = discover_paths()
    if not paths:
        if shutil.which("journalctl"):
            print("No default log files found; falling back to systemd journal.")
            return run_journal(state_path)
        raise SystemExit("No log files found and journalctl is unavailable. Pass paths as arguments or set SENTINELSOC_LOG_PATHS.")
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}
    tails: dict[str, Tail] = {}
    for path in paths:
        try:
            handle = open(path, "rb")
            stat = os.fstat(handle.fileno())
            old = state.get(path, {})
            inode = stat.st_ino
            if START_MODE == "live":
                handle.seek(0, os.SEEK_END)
                offset = handle.tell()
            elif old.get("inode") == inode:
                offset = min(max(0, int(old.get("offset", 0))), stat.st_size)
                handle.seek(offset)
            else:
                offset = 0
            tails[path] = Tail(path, handle, inode, offset)
            if START_MODE == "live":
                print(f"Live mode: ignoring existing lines in {path}.")
            elif offset:
                print(f"Resuming {path} at byte {offset}.")
            else:
                print(f"Hybrid mode: backfilling {path}.")
            state[path] = {"inode": inode, "offset": offset}
        except OSError as exc:
            print(f"Skipping unreadable log {path}: {exc}", file=sys.stderr)
    if not tails:
        raise SystemExit("None of the configured log files could be opened. Check paths and permissions.")
    save_state(state_path, state)
    print(f"Monitoring {len(tails)} Linux log file(s). Checkpoint: {state_path}. Ctrl+C to stop.")
    try:
        while True:
            had_line = False
            for path, tail in list(tails.items()):
                start = tail.handle.tell()
                line = tail.handle.readline()
                if line:
                    had_line = True
                    result = send_line(line, path, tail.inode, start, state_path, state)
                    tail.offset = tail.handle.tell()
                    state[path] = {"inode": tail.inode, "offset": tail.offset}
                    # Accepted or locally quarantined lines are checkpointed; transient errors retry in send_line.
                    if result in {"sent", "skip"}:
                        save_state(state_path, state)
                    continue
                try:
                    current = os.stat(path)
                    if current.st_ino != tail.inode or current.st_size < tail.handle.tell():
                        # Handle rotation and truncation. Drain old file before switching when possible;
                        # at EOF we are safe to switch to the replacement file.
                        tail.handle.close()
                        new_handle = open(path, "rb")
                        tail.handle = new_handle
                        tail.inode = os.fstat(new_handle.fileno()).st_ino
                        tail.offset = 0
                        state[path] = {"inode": tail.inode, "offset": 0}
                        save_state(state_path, state)
                        print(f"Log rotation/truncation detected: {path}; following replacement from start.")
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    print(f"Could not refresh {path}: {exc}", file=sys.stderr)
            if not had_line:
                time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("Stopping Linux collector.")
        return 0
    finally:
        for tail in tails.values():
            try:
                tail.handle.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
