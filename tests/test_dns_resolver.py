import asyncio
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from src.main import (
    ConnectionHandler,
    DnsResolveError,
    IBlacklistManager,
    ProxyConfig,
    ProxyLogger,
    ResolvedTarget,
    Statistics,
)


class NoopBlacklistManager(IBlacklistManager):
    def is_blocked(self, domain: str) -> bool:
        return False

    async def check_domain(self, domain: bytes) -> None:
        return None


class FakeWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def is_closing(self) -> bool:
        return self.closed

    def get_extra_info(self, name):
        if name == "peername":
            return ("127.0.0.1", 54321)
        return None


class DnsResolverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        config = ProxyConfig()
        config.dns_retry_attempts = 3
        config.dns_retry_delay = 0
        config.dns_resolvers = ["8.8.8.8", "1.1.1.1"]
        self.handler = ConnectionHandler(
            config,
            NoopBlacklistManager(),
            Statistics(),
            ProxyLogger(None, None, quiet=True),
        )

    async def test_resolve_target_falls_back_to_tcp_dns_after_system_failure(self):
        with (
            patch.object(
                self.handler,
                "_resolve_via_system",
                side_effect=DnsResolveError(
                    "www.youtube.com",
                    443,
                    "system_resolver_error",
                    1,
                    "system",
                    socket.gaierror(socket.EAI_NONAME, "not known"),
                    resolver_used="system",
                ),
            ) as system_mock,
            patch.object(
                self.handler,
                "_resolve_via_tcp_dns",
                return_value=ResolvedTarget(
                    "142.250.74.110",
                    443,
                    socket.AF_INET,
                    "fallback-tcp:8.8.8.8",
                    1,
                    "8.8.8.8",
                ),
            ) as fallback_mock,
        ):
            resolved = await self.handler._resolve_target("www.youtube.com", 443)

        self.assertEqual(resolved.ip, "142.250.74.110")
        self.assertEqual(resolved.resolver_used, "8.8.8.8")
        self.assertEqual(system_mock.call_count, 3)
        fallback_mock.assert_awaited_once()

    async def test_resolve_target_succeeds_on_third_system_attempt_without_fallback(self):
        results = [
            DnsResolveError(
                "www.youtube.com",
                443,
                "temporary_failure",
                1,
                "system",
                socket.gaierror(socket.EAI_AGAIN, "temporary failure"),
                resolver_used="system",
            ),
            DnsResolveError(
                "www.youtube.com",
                443,
                "temporary_failure",
                1,
                "system",
                socket.gaierror(socket.EAI_AGAIN, "temporary failure"),
                resolver_used="system",
            ),
            ResolvedTarget("142.250.74.110", 443, socket.AF_INET, "system", 1, "system"),
        ]

        async def resolve_side_effect(host, port):
            result = results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        with (
            patch.object(self.handler, "_resolve_via_system", side_effect=resolve_side_effect) as system_mock,
            patch.object(self.handler, "_resolve_via_tcp_dns", new_callable=AsyncMock) as fallback_mock,
        ):
            resolved = await self.handler._resolve_target("www.youtube.com", 443)

        self.assertEqual(resolved.ip, "142.250.74.110")
        self.assertEqual(resolved.attempts, 3)
        self.assertEqual(system_mock.await_count, 3)
        fallback_mock.assert_not_awaited()

    async def test_dns_nxdomain_maps_to_502_response(self):
        conn_key = ("127.0.0.1", 54321)
        self.handler.active_connections[conn_key] = type(
            "ConnInfo",
            (),
            {"dst_domain": "www.youtube.com"},
        )()
        writer = FakeWriter()

        await self.handler._handle_dns_resolve_error(
            writer,
            conn_key,
            DnsResolveError(
                "www.youtube.com",
                443,
                "nxdomain",
                3,
                "fallback-tcp",
                RuntimeError("NXDOMAIN"),
                resolver_used="8.8.8.8,1.1.1.1",
            ),
        )

        response = writer.buffer.decode("utf-8", errors="replace")
        self.assertIn("HTTP/1.1 502 Bad Gateway", response)
        self.assertIn("DNS resolve failed for host www.youtube.com:443", response)
        self.assertNotIn(conn_key, self.handler.active_connections)

    async def test_dns_timeout_maps_to_504_response(self):
        writer = FakeWriter()

        await self.handler._handle_dns_resolve_error(
            writer,
            ("127.0.0.1", 54321),
            DnsResolveError(
                "www.youtube.com",
                443,
                "timeout",
                3,
                "fallback-tcp",
                asyncio.TimeoutError(),
                resolver_used="8.8.8.8",
            ),
        )

        self.assertIn("HTTP/1.1 504 Gateway Timeout", writer.buffer.decode())

    async def test_failed_lookup_does_not_poison_future_resolve(self):
        with patch.object(
            self.handler,
            "_resolve_via_system",
            side_effect=DnsResolveError(
                "www.youtube.com",
                443,
                "system_resolver_error",
                1,
                "system",
                socket.gaierror(socket.EAI_NONAME, "not known"),
                resolver_used="system",
            ),
        ), patch.object(
            self.handler,
            "_resolve_via_tcp_dns",
            side_effect=DnsResolveError(
                "www.youtube.com",
                443,
                "timeout",
                2,
                "fallback-tcp",
                asyncio.TimeoutError(),
                resolver_used="8.8.8.8",
            ),
        ):
            with self.assertRaises(DnsResolveError):
                await self.handler._resolve_target("www.youtube.com", 443)

        with patch.object(
            self.handler,
            "_resolve_via_system",
            return_value=ResolvedTarget(
                "142.250.74.110", 443, socket.AF_INET, "system", 1, "system"
            ),
        ):
            resolved = await self.handler._resolve_target("www.youtube.com", 443)

        self.assertEqual(resolved.ip, "142.250.74.110")

    async def test_fallback_failure_preserves_final_reason_and_system_context(self):
        with patch.object(
            self.handler,
            "_resolve_via_system",
            side_effect=DnsResolveError(
                "googleads.g.doubleclick.net",
                443,
                "system_resolver_error",
                1,
                "system",
                socket.gaierror(socket.EAI_NONAME, "not known"),
                resolver_used="system",
            ),
        ), patch.object(
            self.handler,
            "_resolve_via_tcp_dns",
            side_effect=DnsResolveError(
                "googleads.g.doubleclick.net",
                443,
                "fallback_resolver_error",
                2,
                "fallback-tcp",
                RuntimeError("Fallback resolver 1.1.1.1 returned temporary_failure"),
                resolver_used="8.8.8.8,1.1.1.1",
            ),
        ):
            with self.assertRaises(DnsResolveError) as context:
                await self.handler._resolve_target("googleads.g.doubleclick.net", 443)

        error = context.exception
        self.assertEqual(error.reason_code, "fallback_resolver_error")
        self.assertEqual(error.system_reason_code, "system_resolver_error")
        self.assertEqual(type(error.system_exception).__name__, "gaierror")

    async def test_dns_error_log_contains_final_and_system_reason(self):
        messages = []
        self.handler.logger.log_error = messages.append
        writer = FakeWriter()

        await self.handler._handle_dns_resolve_error(
            writer,
            ("127.0.0.1", 54321),
            DnsResolveError(
                "static.doubleclick.net",
                443,
                "fallback_resolver_error",
                3,
                "fallback-tcp",
                RuntimeError("Fallback resolver 1.1.1.1 returned temporary_failure"),
                resolver_used="8.8.8.8,1.1.1.1",
                system_reason_code="system_resolver_error",
                system_exception=socket.gaierror(socket.EAI_NONAME, "not known"),
            ),
        )

        self.assertEqual(len(messages), 1)
        self.assertIn("reason=fallback_resolver_error", messages[0])
        self.assertIn("system_reason=system_resolver_error", messages[0])
        self.assertIn("system_exception_type=gaierror", messages[0])

    async def test_https_connect_uses_resolved_ip_for_open_connection(self):
        reader = AsyncMock()
        reader.read.return_value = b""
        client_writer = FakeWriter()
        remote_writer = AsyncMock()
        remote_writer.is_closing.return_value = False

        with (
            patch.object(
                self.handler,
                "_resolve_target",
                return_value=ResolvedTarget(
                    "142.250.74.110",
                    443,
                    socket.AF_INET,
                    "fallback-tcp:8.8.8.8",
                    3,
                    "8.8.8.8",
                ),
            ),
            patch("nodpi.proxy.asyncio.open_connection", new_callable=AsyncMock) as open_connection_mock,
            patch.object(self.handler, "_handle_initial_tls_data", new_callable=AsyncMock),
            patch.object(self.handler, "_setup_piping", new_callable=AsyncMock),
        ):
            open_connection_mock.return_value = (AsyncMock(), remote_writer)
            await self.handler._handle_https_connection(
                reader,
                client_writer,
                b"www.youtube.com",
                443,
                ("127.0.0.1", 54321),
                type(
                    "ConnInfo",
                    (),
                    {"traffic_in": 0, "dst_domain": "www.youtube.com"},
                )(),
            )

        args, kwargs = open_connection_mock.await_args
        self.assertEqual(args[0], "142.250.74.110")
        self.assertEqual(args[1], 443)
        self.assertEqual(kwargs["family"], socket.AF_INET)


if __name__ == "__main__":
    unittest.main()
