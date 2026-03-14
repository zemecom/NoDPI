"""Shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ConnectionInfo:
    """Connection metadata."""

    src_ip: str
    dst_domain: str
    method: str
    start_time: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    traffic_in: int = 0
    traffic_out: int = 0


@dataclass
class ResolvedTarget:
    """Resolved connection target."""

    ip: str
    port: int
    family: int
    resolver_path: str
    attempts: int
    resolver_used: str


class DnsResolveError(Exception):
    """Structured DNS resolution error."""

    def __init__(
        self,
        host: str,
        port: int,
        reason_code: str,
        attempts: int,
        resolver_path: str,
        last_exception: Optional[BaseException] = None,
        resolver_used: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.reason_code = reason_code
        self.attempts = attempts
        self.resolver_path = resolver_path
        self.last_exception = last_exception
        self.resolver_used = resolver_used or "-"
        super().__init__(
            f"DNS resolve failed for {host}:{port} ({reason_code}, {resolver_path})"
        )
