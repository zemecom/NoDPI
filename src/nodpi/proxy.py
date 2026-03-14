"""Proxy server implementation."""

from __future__ import annotations

import asyncio
import base64
import random
import socket
import sys
import traceback

from typing import Dict, List, Optional, Tuple

from .blacklists import AutoBlacklistManager, NoBlacklistManager
from .config import ProxyConfig
from .contracts import IBlacklistManager, IConnectionHandler, ILogger, IStatistics
from .dns import DNSResolver
from .models import ConnectionInfo, DnsResolveError, ResolvedTarget
from .runtime_ui import ProxyRuntimeUI


class ConnectionHandler(IConnectionHandler):
    """Handles individual client connections."""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):
        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.auth_enabled = config.username is not None and config.password is not None
        self.dns_resolver = DNSResolver(config)
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle one incoming proxy connection."""

        conn_key = None
        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await asyncio.wait_for(
                reader.read(self.config.read_chunk_size),
                timeout=self.config.io_timeout,
            )

            if not http_data:
                writer.close()
                return

            method, host, port = self._parse_http_request(http_data)
            conn_key = (client_ip, client_port)
            conn_info = ConnectionInfo(client_ip, host.decode(), method.decode())

            if method == b"CONNECT" and isinstance(
                self.blacklist_manager, AutoBlacklistManager
            ):
                await self.blacklist_manager.check_domain(host)

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            self.statistics.update_traffic(0, len(http_data))
            conn_info.traffic_out += len(http_data)

            if not await self._check_proxy_authorization(http_data, writer):
                return

            if method == b"CONNECT":
                await self._handle_https_connection(
                    reader, writer, host, port, conn_key, conn_info
                )
            else:
                await self._handle_http_connection(
                    reader, writer, http_data, host, port, conn_key
                )
        except DnsResolveError as error:
            await self._handle_dns_resolve_error(writer, conn_key, error)
        except asyncio.TimeoutError:
            error = DnsResolveError(
                host="unknown",
                port=0,
                reason_code="timeout",
                attempts=1,
                resolver_path="connection",
                last_exception=None,
            )
            await self._handle_dns_resolve_error(writer, conn_key, error)
        except Exception:
            await self._handle_connection_error(writer, conn_key)

    def _parse_http_request(self, http_data: bytes) -> Tuple[bytes, bytes, int]:
        """Parse HTTP request line and host header."""

        headers = http_data.split(b"\r\n")
        first_line = headers[0].split(b" ")
        method = first_line[0]
        url = first_line[1]

        if method == b"CONNECT":
            host_port = url.split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            host_header = next(
                (item for item in headers if item.startswith(b"Host: ")), None
            )
            if not host_header:
                raise ValueError("Missing Host header")
            host_port = host_header[6:].split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80

        return method, host, port

    async def _check_proxy_authorization(
        self, http_data: bytes, writer: asyncio.StreamWriter
    ) -> bool:
        """Validate proxy credentials if auth is enabled."""

        if not self.auth_enabled:
            return True

        headers = http_data.split(b"\r\n")
        auth_header = None
        for line in headers:
            if line.lower().startswith(b"proxy-authorization:"):
                auth_header = line
                break

        if auth_header is None:
            await self._send_407_response(writer)
            return False

        parts = auth_header.split(b" ", 2)
        if len(parts) != 3 or parts[1].lower() != b"basic":
            await self._send_407_response(writer)
            return False

        try:
            decoded = base64.b64decode(parts[2].strip()).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            await self._send_407_response(writer)
            return False

        if username != self.config.username or password != self.config.password:
            await self._send_407_response(writer)
            return False

        return True

    async def _send_407_response(self, writer: asyncio.StreamWriter):
        """Send proxy-auth challenge."""

        response = (
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            'Proxy-Authenticate: Basic realm="NoDPI Proxy"\r\n'
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(response.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def _is_ip_address(self, host: str) -> bool:
        """Compatibility wrapper around the extracted DNS resolver."""

        return self.dns_resolver.is_ip_address(host)

    def _build_dns_query(self, host: str) -> bytes:
        """Compatibility wrapper around the extracted DNS resolver."""

        return self.dns_resolver.build_dns_query(host)

    def _read_dns_name(self, message: bytes, offset: int) -> Tuple[str, int]:
        """Compatibility wrapper around the extracted DNS resolver."""

        return self.dns_resolver.read_dns_name(message, offset)

    def _parse_dns_response(self, payload: bytes) -> Tuple[str, List[str]]:
        """Compatibility wrapper around the extracted DNS resolver."""

        return self.dns_resolver.parse_dns_response(payload)

    async def _resolve_via_system(self, host: str, port: int) -> ResolvedTarget:
        """Compatibility wrapper around the extracted DNS resolver."""

        return await self.dns_resolver.resolve_via_system(host, port)

    async def _resolve_via_tcp_dns(self, host: str, port: int) -> ResolvedTarget:
        """Compatibility wrapper around the extracted DNS resolver."""

        return await self.dns_resolver.resolve_via_tcp_dns(host, port)

    async def _resolve_target(self, host: str, port: int) -> ResolvedTarget:
        """Resolve host with system retries and TCP DNS fallback."""

        if self._is_ip_address(host):
            return ResolvedTarget(
                host,
                port,
                socket.AF_INET6 if ":" in host else socket.AF_INET,
                "direct-ip",
                0,
                "direct-ip",
            )

        last_error: Optional[DnsResolveError] = None
        attempts = max(1, self.config.dns_retry_attempts)
        for attempt in range(1, attempts + 1):
            try:
                resolved = await self._resolve_via_system(host, port)
                resolved.attempts = attempt
                return resolved
            except DnsResolveError as exc:
                exc.attempts = attempt
                last_error = exc
                if attempt < attempts:
                    await asyncio.sleep(self.config.dns_retry_delay)

        try:
            resolved = await self._resolve_via_tcp_dns(host, port)
            resolved.attempts = attempts
            return resolved
        except DnsResolveError as fallback_error:
            fallback_error.attempts = attempts
            if last_error:
                fallback_error.system_reason_code = last_error.reason_code
                fallback_error.system_exception = last_error.last_exception
            raise fallback_error

    async def _open_resolved_connection(
        self, resolved: ResolvedTarget
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Compatibility wrapper around the extracted DNS resolver."""

        return await self.dns_resolver.open_resolved_connection(resolved)

    async def _handle_https_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        port: int,
        conn_key: Tuple,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle HTTPS CONNECT requests."""

        resolved = await self._resolve_target(host.decode(), port)
        remote_reader, remote_writer = await self._open_resolved_connection(resolved)

        response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        self.statistics.update_traffic(len(response), 0)
        conn_info.traffic_in += len(response)
        writer.write(response)
        await writer.drain()

        await self._handle_initial_tls_data(reader, remote_writer, host, conn_info)
        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    async def _handle_http_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        http_data: bytes,
        host: bytes,
        port: int,
        conn_key: Tuple,
    ) -> None:
        """Handle plain HTTP requests."""

        resolved = await self._resolve_target(host.decode(), port)
        remote_reader, remote_writer = await self._open_resolved_connection(resolved)
        remote_writer.write(http_data)
        await asyncio.wait_for(remote_writer.drain(), timeout=self.config.io_timeout)

        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    def _extract_sni_position(self, data):
        """Find the SNI position inside a TLS ClientHello."""

        index = 0
        while index < len(data) - 8:
            if all(data[index + item] == 0x00 for item in [0, 1, 2, 4, 6, 7]):
                ext_len = data[index + 3]
                server_name_list_len = data[index + 5]
                server_name_len = data[index + 8]
                if (
                    ext_len - server_name_list_len == 2
                    and server_name_list_len - server_name_len == 3
                ):
                    sni_start = index + 9
                    sni_end = sni_start + server_name_len
                    return sni_start, sni_end
            index += 1
        return None

    async def _handle_initial_tls_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        conn_info: ConnectionInfo,
    ) -> None:
        """Read and optionally fragment the first TLS packet."""

        try:
            head = await asyncio.wait_for(reader.read(5), timeout=self.config.io_timeout)
            data = await asyncio.wait_for(
                reader.read(2048), timeout=self.config.io_timeout
            )
        except Exception:
            self.logger.log_error(f"{host.decode()} : {traceback.format_exc()}")
            return

        should_fragment = True
        if not isinstance(self.blacklist_manager, NoBlacklistManager):
            should_fragment = self.blacklist_manager.is_blocked(conn_info.dst_domain)

        if not should_fragment:
            await self._forward_tls_without_fragmentation(head + data, writer, conn_info)
            return

        combined_parts = self._fragment_tls_payload(data)
        writer.write(combined_parts)
        await asyncio.wait_for(writer.drain(), timeout=self.config.io_timeout)
        self.statistics.update_traffic(0, len(combined_parts))
        conn_info.traffic_out += len(combined_parts)

    async def _forward_tls_without_fragmentation(
        self,
        payload: bytes,
        writer: asyncio.StreamWriter,
        conn_info: ConnectionInfo,
    ) -> None:
        """Forward the TLS ClientHello as-is."""

        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()
        writer.write(payload)
        await asyncio.wait_for(writer.drain(), timeout=self.config.io_timeout)
        self.statistics.update_traffic(0, len(payload))
        conn_info.traffic_out += len(payload)

    def _fragment_tls_payload(self, data: bytes) -> bytes:
        """Split the initial TLS payload according to the selected method."""

        self.statistics.increment_total_connections()
        self.statistics.increment_blocked_connections()

        parts = []
        if self.config.fragment_method == "sni":
            sni_pos = self._extract_sni_position(data)
            if sni_pos:
                part_start = data[: sni_pos[0]]
                sni_data = data[sni_pos[0] : sni_pos[1]]
                part_end = data[sni_pos[1] :]
                middle = (len(sni_data) + 1) // 2
                parts.append(
                    bytes.fromhex("160304")
                    + len(part_start).to_bytes(2, "big")
                    + part_start
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(sni_data[:middle]).to_bytes(2, "big")
                    + sni_data[:middle]
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(sni_data[middle:]).to_bytes(2, "big")
                    + sni_data[middle:]
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(part_end).to_bytes(2, "big")
                    + part_end
                )
        elif self.config.fragment_method == "random":
            host_end = data.find(b"\x00")
            if host_end != -1:
                part_data = (
                    bytes.fromhex("160304")
                    + (host_end + 1).to_bytes(2, "big")
                    + data[: host_end + 1]
                )
                parts.append(part_data)
                data = data[host_end + 1 :]
            while data:
                chunk_len = random.randint(1, len(data))
                part_data = (
                    bytes.fromhex("160304")
                    + chunk_len.to_bytes(2, "big")
                    + data[:chunk_len]
                )
                parts.append(part_data)
                data = data[chunk_len:]

        return b"".join(parts)

    async def _setup_piping(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_key: Tuple,
    ) -> None:
        """Create the background tasks that pipe data both ways."""

        async with self.tasks_lock:
            self.tasks.extend(
                [
                    asyncio.create_task(
                        self._pipe_data(client_reader, remote_writer, "out", conn_key)
                    ),
                    asyncio.create_task(
                        self._pipe_data(remote_reader, client_writer, "in", conn_key)
                    ),
                ]
            )

    async def _pipe_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        conn_key: Tuple,
    ) -> None:
        """Pipe data in one direction until EOF, timeout, or cancellation."""

        conn_info: Optional[ConnectionInfo] = None
        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await asyncio.wait_for(
                    reader.read(self.config.read_chunk_size),
                    timeout=self.config.io_timeout,
                )
                if not data:
                    break

                if direction == "out":
                    self.statistics.update_traffic(0, len(data))
                else:
                    self.statistics.update_traffic(len(data), 0)

                async with self.connections_lock:
                    conn_info = self.active_connections.get(conn_key)
                    if conn_info:
                        if direction == "out":
                            conn_info.traffic_out += len(data)
                        else:
                            conn_info.traffic_in += len(data)

                writer.write(data)
                await asyncio.wait_for(writer.drain(), timeout=self.config.io_timeout)
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            self.logger.log_error(
                f"pipe_timeout direction={direction} conn_key={conn_key}"
            )
        except Exception:
            domain = conn_info.dst_domain if conn_info else "unknown"
            self.logger.log_error(f"{domain} : {traceback.format_exc()}")
        finally:
            await self._finalize_pipe(writer, conn_key)

    async def _finalize_pipe(
        self, writer: asyncio.StreamWriter, conn_key: Tuple
    ) -> None:
        """Close one writer and emit access log once the connection is done."""

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)
            if conn_info:
                self.logger.log_access(
                    f"{conn_info.start_time} {conn_info.src_ip} "
                    f"{conn_info.method} {conn_info.dst_domain} "
                    f"{conn_info.traffic_in} {conn_info.traffic_out}"
                )

    async def _send_error_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        status_text: str,
        message: str,
    ) -> None:
        """Send a plain-text proxy error response."""

        body = message.encode("utf-8", errors="replace")
        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        writer.write(response)
        await writer.drain()
        self.statistics.update_traffic(len(response), 0)

    async def _handle_connection_error(
        self, writer: asyncio.StreamWriter, conn_key: Tuple
    ) -> None:
        """Handle generic unexpected connection failures."""

        try:
            await self._send_error_response(
                writer,
                500,
                "Internal Server Error",
                "Proxy internal error",
            )
        except Exception:
            pass

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)

        self.statistics.increment_total_connections()
        self.statistics.increment_error_connections()
        domain = conn_info.dst_domain if conn_info else "unknown"
        self.logger.log_error(f"{domain} : {traceback.format_exc()}")

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def _handle_dns_resolve_error(
        self, writer: asyncio.StreamWriter, conn_key: Tuple, error: DnsResolveError
    ) -> None:
        """Handle DNS failures with structured logs and mapped HTTP errors."""

        status_map = {
            "nxdomain": (502, "Bad Gateway"),
            "temporary_failure": (502, "Bad Gateway"),
            "system_resolver_error": (502, "Bad Gateway"),
            "fallback_resolver_error": (502, "Bad Gateway"),
            "timeout": (504, "Gateway Timeout"),
        }
        status_code, status_text = status_map.get(
            error.reason_code, (502, "Bad Gateway")
        )
        message = (
            f"DNS resolve failed for host {error.host}:{error.port} "
            f"({error.reason_code}, {error.resolver_path})"
        )

        try:
            await self._send_error_response(writer, status_code, status_text, message)
        except Exception:
            pass

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)

        self.statistics.increment_total_connections()
        self.statistics.increment_error_connections()

        last_exception = error.last_exception
        last_exception_type = type(last_exception).__name__ if last_exception else "-"
        last_exception_text = str(last_exception) if last_exception else "-"
        system_exception = error.system_exception
        system_exception_type = (
            type(system_exception).__name__ if system_exception else "-"
        )
        system_exception_text = str(system_exception) if system_exception else "-"
        dst_domain = conn_info.dst_domain if conn_info else error.host
        self.logger.log_error(
            "dns_error "
            f"host={error.host} port={error.port} reason={error.reason_code} "
            f"system_reason={error.system_reason_code or '-'} "
            f"attempts={error.attempts} resolver_path={error.resolver_path} "
            f"resolver_used={error.resolver_used} exception_type={last_exception_type} "
            f"exception={last_exception_text} "
            f"system_exception_type={system_exception_type} "
            f"system_exception={system_exception_text} dst_domain={dst_domain}"
        )

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def cleanup_tasks(self) -> None:
        """Periodically forget completed piping tasks."""

        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [task for task in self.tasks if not task.done()]


class ProxyServer:
    """Main proxy server class."""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):
        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = ConnectionHandler(
            config, blacklist_manager, statistics, logger
        )
        self.runtime_ui = ProxyRuntimeUI(config, blacklist_manager, statistics, logger)
        self.server = None
        logger.set_error_counter_callback(statistics.increment_error_connections)

    async def run(self) -> None:
        """Start the proxy server and serve forever."""

        if not self.config.quiet:
            await self.runtime_ui.print_banner()

        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.host,
                self.config.port,
            )
        except OSError:
            self.logger.error(
                f"\033[91m[ERROR]: Failed to start proxy on this address "
                f"({self.config.host}:{self.config.port}). "
                "It looks like the port is already in use\033[0m"
            )
            sys.exit(1)

        if not self.config.quiet:
            asyncio.create_task(self.runtime_ui.display_stats())
        asyncio.create_task(self.connection_handler.cleanup_tasks())
        await self.server.serve_forever()

    async def shutdown(self) -> None:
        """Stop listening socket and cancel active pipe tasks."""

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        for task in self.connection_handler.tasks:
            task.cancel()
