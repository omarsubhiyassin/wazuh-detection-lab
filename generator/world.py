"""Deterministic lab environment: hosts, users, IPs, and benign values.

Everything is seeded off a single RNG so a given --seed reproduces the exact
same logs and ground truth.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    os: str  # "linux" | "windows"


@dataclass(frozen=True)
class User:
    name: str
    kind: str  # "human" | "service"


LINUX_HOSTS = [
    Host("web-01", "10.0.10.11", "linux"),
    Host("web-02", "10.0.10.12", "linux"),
    Host("app-01", "10.0.10.21", "linux"),
]

WINDOWS_HOSTS = [
    Host("WIN-FIN-01", "10.0.20.31", "windows"),
    Host("WIN-HR-02", "10.0.20.32", "windows"),
    Host("WIN-DEV-03", "10.0.20.33", "windows"),
]

HUMAN_USERS = [User(n, "human") for n in ("jsmith", "mchen", "apatel", "rkumar", "lgarcia")]
SERVICE_USERS = [User(n, "service") for n in ("deploy", "svc_backup", "www-data", "gitlab-runner")]

# Office / VPN egress addresses that legitimate SSH comes from.
BENIGN_SRC_IPS = ["198.51.100.24", "198.51.100.25", "203.0.113.10"]

# Popular destinations for benign DNS lookups.
BENIGN_DOMAINS = [
    "www.google.com", "update.microsoft.com", "github.com", "slack.com",
    "api.datadoghq.com", "ubuntu.com", "cdn.jsdelivr.net", "outlook.office365.com",
    "login.microsoftonline.com", "s3.amazonaws.com",
]

INTERNAL_RESOLVER = "10.0.20.1"


class World:
    """Holds the seeded RNG plus monotonic counters for GUIDs / record IDs."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.linux_hosts = LINUX_HOSTS
        self.windows_hosts = WINDOWS_HOSTS
        self.human_users = HUMAN_USERS
        self.service_users = SERVICE_USERS
        self._rid = 10_000
        self._pid_pool = list(range(2000, 60000))

    # --- lookups ---------------------------------------------------------
    def ip_of(self, host_name: str) -> str:
        for h in (*self.linux_hosts, *self.windows_hosts):
            if h.name == host_name:
                return h.ip
        raise KeyError(f"unknown host {host_name!r}")

    # --- deterministic identifiers --------------------------------------
    def record_id(self) -> int:
        self._rid += 1
        return self._rid

    def pid(self) -> int:
        return self.rng.choice(self._pid_pool)

    def guid(self) -> str:
        r = self.rng
        return "{%08X-%04X-%04X-%04X-%012X}" % (
            r.getrandbits(32), r.getrandbits(16), r.getrandbits(16),
            r.getrandbits(16), r.getrandbits(48),
        )
