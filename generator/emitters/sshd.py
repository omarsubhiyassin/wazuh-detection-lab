"""Linux OpenSSH auth.log lines (syslog format).

Wazuh's built-in sshd decoder + ruleset parse these:
  5710 attempt to login using a non-existent user
  5716 SSHD authentication failed
  5715 SSHD authentication success
  5720 multiple SSHD authentication failures (brute force)
"""
from __future__ import annotations

from datetime import datetime, timezone


def _header(ts: float, host: str, pid: int, proc: str = "sshd") -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    # syslog uses a space-padded day; build it manually (%e is not portable to Windows).
    stamp = f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"
    return f"{stamp} {host} {proc}[{pid}]:"


def failed_invalid_user(ts: float, *, host: str, user: str, src_ip: str, port: int, pid: int) -> str:
    return (f"{_header(ts, host, pid)} Failed password for invalid user "
            f"{user} from {src_ip} port {port} ssh2")


def failed_password(ts: float, *, host: str, user: str, src_ip: str, port: int, pid: int) -> str:
    return f"{_header(ts, host, pid)} Failed password for {user} from {src_ip} port {port} ssh2"


def accepted_password(ts: float, *, host: str, user: str, src_ip: str, port: int, pid: int) -> str:
    return f"{_header(ts, host, pid)} Accepted password for {user} from {src_ip} port {port} ssh2"


def accepted_publickey(ts: float, *, host: str, user: str, src_ip: str, port: int, pid: int,
                       keytype: str = "ED25519",
                       fp: str = "SHA256:9y1kM2m7bqKQp0Xw3v8sFqz2Jd6h1oQe5n3lRt8uAc") -> str:
    return (f"{_header(ts, host, pid)} Accepted publickey for {user} from {src_ip} "
            f"port {port} ssh2: {keytype} {fp}")
