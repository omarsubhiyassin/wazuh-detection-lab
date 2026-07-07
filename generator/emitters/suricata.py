"""Suricata eve.json events (one JSON object per line).

Wazuh's Suricata decoder maps these to data.* fields (data.dns.rrname,
data.src_ip, ...). The DNS-beacon detection keys off data.dns.rrname plus
frequency.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def dns_query(ts: float, *, src_ip: str, dest_ip: str, rrname: str, rrtype: str = "A",
              src_port: int = 0, tx_id: int = 0) -> str:
    obj = {
        "timestamp": _ts(ts),
        "flow_id": tx_id or 0,
        "event_type": "dns",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": 53,
        "proto": "UDP",
        "dns": {"type": "query", "id": tx_id, "rrname": rrname, "rrtype": rrtype},
    }
    return json.dumps(obj, separators=(",", ":"))


def flow(ts: float, *, src_ip: str, dest_ip: str, dest_port: int, proto: str = "TCP",
         app_proto: str = "tls", bytes_toserver: int = 0, bytes_toclient: int = 0) -> str:
    obj = {
        "timestamp": _ts(ts),
        "event_type": "flow",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "app_proto": app_proto,
        "flow": {"bytes_toserver": bytes_toserver, "bytes_toclient": bytes_toclient},
    }
    return json.dumps(obj, separators=(",", ":"))
