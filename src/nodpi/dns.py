"""DNS resolution helpers for proxy connections."""

from __future__ import annotations

import asyncio
import random
import socket
import struct
from ipaddress import ip_address
from typing import List, Optional, Tuple

from .config import ProxyConfig
from .models import DnsResolveError, ResolvedTarget


class DNSResolver:
    """Resolve proxy targets with retries and DNS-over-TCP fallback."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.out_host = config.out_host

    def is_ip_address(self, host: str) -> bool:
        """Check whether host is already an IP address."""

        try:
            ip_address(host)
            return True
        except ValueError:
            return False

    def build_dns_query(self, host: str) -> bytes:
        """Build a minimal DNS A query."""

        transaction_id = random.randint(0, 0xFFFF)
        header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        labels = []
        for label in host.rstrip(".").split("."):
            label_bytes = label.encode("idna")
            labels.append(bytes([len(label_bytes)]))
            labels.append(label_bytes)
        question = b"".join(labels) + b"\x00" + struct.pack("!HH", 1, 1)
        return header + question

    def read_dns_name(self, message: bytes, offset: int) -> Tuple[str, int]:
        """Read a possibly compressed DNS name."""

        labels = []
        jumped = False
        next_offset = offset

        while True:
            length = message[offset]
            if length == 0:
                offset += 1
                if not jumped:
                    next_offset = offset
                break

            if length & 0xC0 == 0xC0:
                pointer = ((length & 0x3F) << 8) | message[offset + 1]
                if not jumped:
                    next_offset = offset + 2
                offset = pointer
                jumped = True
                continue

            offset += 1
            labels.append(message[offset : offset + length].decode("idna"))
            offset += length
            if not jumped:
                next_offset = offset

        return ".".join(labels), next_offset

    def parse_dns_response(self, payload: bytes) -> Tuple[str, List[str]]:
        """Parse DNS A answers from a TCP DNS response."""

        if len(payload) < 12:
            raise ValueError("DNS response too short")

        _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
        rcode = flags & 0x000F
        offset = 12

        for _ in range(qdcount):
            _, offset = self.read_dns_name(payload, offset)
            offset += 4

        answers = []
        for _ in range(ancount):
            _, offset = self.read_dns_name(payload, offset)
            rtype, rclass, _, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
            offset += 10
            rdata = payload[offset : offset + rdlength]
            offset += rdlength
            if rtype == 1 and rclass == 1 and rdlength == 4:
                answers.append(socket.inet_ntoa(rdata))

        if rcode == 3:
            return "nxdomain", answers
        if rcode != 0:
            return "temporary_failure", answers
        if answers:
            return "ok", answers
        return "temporary_failure", answers

    async def resolve_via_system(self, host: str, port: int) -> ResolvedTarget:
        """Resolve host via the system resolver."""

        loop = asyncio.get_running_loop()
        family = socket.AF_INET if self.config.dns_prefer_ipv4 else socket.AF_UNSPEC

        try:
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(
                    host,
                    port,
                    family=family,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                ),
                timeout=self.config.dns_system_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise DnsResolveError(host, port, "timeout", 1, "system", exc, "system") from exc
        except socket.gaierror as exc:
            reason_code = (
                "temporary_failure" if exc.errno == socket.EAI_AGAIN else "system_resolver_error"
            )
            raise DnsResolveError(host, port, reason_code, 1, "system", exc, "system") from exc

        if not addr_info:
            raise DnsResolveError(
                host,
                port,
                "system_resolver_error",
                1,
                "system",
                RuntimeError("System resolver returned no addresses"),
                "system",
            )

        selected = addr_info[0]
        sockaddr = selected[4]
        return ResolvedTarget(
            ip=sockaddr[0],
            port=sockaddr[1],
            family=selected[0],
            resolver_path="system",
            attempts=1,
            resolver_used="system",
        )

    async def resolve_via_tcp_dns(self, host: str, port: int) -> ResolvedTarget:
        """Resolve host via fallback TCP DNS resolvers."""

        saw_timeout = False
        saw_nxdomain = False
        last_exception: Optional[BaseException] = None
        query = self.build_dns_query(host)
        packet = struct.pack("!H", len(query)) + query

        for resolver in self.config.dns_resolvers:
            reader = None
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(resolver, 53),
                    timeout=self.config.dns_tcp_timeout,
                )
                writer.write(packet)
                await asyncio.wait_for(writer.drain(), timeout=self.config.dns_tcp_timeout)
                raw_length = await asyncio.wait_for(
                    reader.readexactly(2), timeout=self.config.dns_tcp_timeout
                )
                response_length = struct.unpack("!H", raw_length)[0]
                payload = await asyncio.wait_for(
                    reader.readexactly(response_length),
                    timeout=self.config.dns_tcp_timeout,
                )
                status, answers = self.parse_dns_response(payload)
                if status == "ok" and answers:
                    return ResolvedTarget(
                        ip=answers[0],
                        port=port,
                        family=socket.AF_INET,
                        resolver_path=f"fallback-tcp:{resolver}",
                        attempts=1,
                        resolver_used=resolver,
                    )
                if status == "nxdomain":
                    saw_nxdomain = True
                    last_exception = RuntimeError(f"NXDOMAIN confirmed by TCP resolver {resolver}")
                    continue
                last_exception = RuntimeError(f"Fallback resolver {resolver} returned {status}")
            except asyncio.TimeoutError as exc:
                saw_timeout = True
                last_exception = exc
            except (
                asyncio.IncompleteReadError,
                ConnectionError,
                OSError,
                ValueError,
            ) as exc:
                last_exception = exc
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        if saw_nxdomain and not saw_timeout:
            raise DnsResolveError(
                host,
                port,
                "nxdomain",
                len(self.config.dns_resolvers),
                "fallback-tcp",
                last_exception,
                ",".join(self.config.dns_resolvers),
            )

        reason_code = "timeout" if saw_timeout and last_exception else "fallback_resolver_error"
        raise DnsResolveError(
            host,
            port,
            reason_code,
            len(self.config.dns_resolvers),
            "fallback-tcp",
            last_exception,
            ",".join(self.config.dns_resolvers),
        )

    async def resolve_target(self, host: str, port: int) -> ResolvedTarget:
        """Resolve host with system retries and TCP DNS fallback."""

        if self.is_ip_address(host):
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            return ResolvedTarget(host, port, family, "direct-ip", 0, "direct-ip")

        last_error: Optional[DnsResolveError] = None
        attempts = max(1, self.config.dns_retry_attempts)
        for attempt in range(1, attempts + 1):
            try:
                resolved = await self.resolve_via_system(host, port)
                resolved.attempts = attempt
                return resolved
            except DnsResolveError as exc:
                exc.attempts = attempt
                last_error = exc
                if attempt < attempts:
                    await asyncio.sleep(self.config.dns_retry_delay)

        try:
            resolved = await self.resolve_via_tcp_dns(host, port)
            resolved.attempts = attempts
            return resolved
        except DnsResolveError as fallback_error:
            fallback_error.attempts = attempts
            if last_error:
                fallback_error.system_reason_code = last_error.reason_code
                fallback_error.system_exception = last_error.last_exception
            raise fallback_error

    async def open_resolved_connection(
        self, resolved: ResolvedTarget
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a TCP connection to a pre-resolved target."""

        return await asyncio.wait_for(
            asyncio.open_connection(
                resolved.ip,
                resolved.port,
                family=resolved.family,
                local_addr=(self.out_host, 0) if self.out_host else None,
            ),
            timeout=self.config.connect_timeout,
        )
