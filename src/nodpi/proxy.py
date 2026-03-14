"""Proxy server implementation."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import socket
import struct
import sys
import textwrap
import time
import traceback

from datetime import datetime
from ipaddress import ip_address
from typing import Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

from .blacklists import AutoBlacklistManager, NoBlacklistManager
from .config import ProxyConfig
from .contracts import IBlacklistManager, IConnectionHandler, ILogger, IStatistics
from .models import ConnectionInfo, DnsResolveError, ResolvedTarget
from .version import __version__


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
        self.out_host = self.config.out_host
        self.auth_enabled = config.username is not None and config.password is not None
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn_key = None
        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await asyncio.wait_for(
                reader.read(self.config.read_chunk_size), timeout=self.config.io_timeout
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
        headers = http_data.split(b"\r\n")
        first_line = headers[0].split(b" ")
        method = first_line[0]
        url = first_line[1]

        if method == b"CONNECT":
            host_port = url.split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            host_header = next((item for item in headers if item.startswith(b"Host: ")), None)
            if not host_header:
                raise ValueError("Missing Host header")

            host_port = host_header[6:].split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80
        return method, host, port

    async def _check_proxy_authorization(
        self, http_data: bytes, writer: asyncio.StreamWriter
    ) -> bool:
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
        try:
            ip_address(host)
            return True
        except ValueError:
            return False

    def _build_dns_query(self, host: str) -> bytes:
        transaction_id = random.randint(0, 0xFFFF)
        header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        labels = []
        for label in host.rstrip(".").split("."):
            label_bytes = label.encode("idna")
            labels.append(bytes([len(label_bytes)]))
            labels.append(label_bytes)
        question = b"".join(labels) + b"\x00" + struct.pack("!HH", 1, 1)
        return header + question

    def _read_dns_name(self, message: bytes, offset: int) -> Tuple[str, int]:
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
            labels.append(message[offset: offset + length].decode("idna"))
            offset += length
            if not jumped:
                next_offset = offset
        return ".".join(labels), next_offset

    def _parse_dns_response(self, payload: bytes) -> Tuple[str, List[str]]:
        if len(payload) < 12:
            raise ValueError("DNS response too short")
        _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
        rcode = flags & 0x000F
        offset = 12
        for _ in range(qdcount):
            _, offset = self._read_dns_name(payload, offset)
            offset += 4

        answers = []
        for _ in range(ancount):
            _, offset = self._read_dns_name(payload, offset)
            rtype, rclass, _, rdlength = struct.unpack("!HHIH", payload[offset: offset + 10])
            offset += 10
            rdata = payload[offset: offset + rdlength]
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

    async def _resolve_via_system(self, host: str, port: int) -> ResolvedTarget:
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
            reason_code = "temporary_failure" if exc.errno == socket.EAI_AGAIN else "system_resolver_error"
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

    async def _resolve_via_tcp_dns(self, host: str, port: int) -> ResolvedTarget:
        saw_timeout = False
        saw_nxdomain = False
        last_exception: Optional[BaseException] = None
        query = self._build_dns_query(host)
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
                status, answers = self._parse_dns_response(payload)
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
                    last_exception = RuntimeError(
                        f"NXDOMAIN confirmed by TCP resolver {resolver}"
                    )
                    continue
                last_exception = RuntimeError(f"Fallback resolver {resolver} returned {status}")
            except asyncio.TimeoutError as exc:
                saw_timeout = True
                last_exception = exc
            except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError) as exc:
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
                host, port, "nxdomain", len(self.config.dns_resolvers), "fallback-tcp", last_exception, ",".join(self.config.dns_resolvers)
            )

        reason_code = "timeout" if saw_timeout and last_exception else "fallback_resolver_error"
        raise DnsResolveError(
            host, port, reason_code, len(self.config.dns_resolvers), "fallback-tcp", last_exception, ",".join(self.config.dns_resolvers)
        )

    async def _resolve_target(self, host: str, port: int) -> ResolvedTarget:
        if self._is_ip_address(host):
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            return ResolvedTarget(host, port, family, "direct-ip", 0, "direct-ip")

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
            if last_error and fallback_error.reason_code == "fallback_resolver_error":
                fallback_error.reason_code = last_error.reason_code
                fallback_error.last_exception = fallback_error.last_exception or last_error.last_exception
            raise fallback_error

    async def _open_resolved_connection(
        self, resolved: ResolvedTarget
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(
                resolved.ip,
                resolved.port,
                family=resolved.family,
                local_addr=(self.out_host, 0) if self.out_host else None,
            ),
            timeout=self.config.connect_timeout,
        )

    async def _handle_https_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        port: int,
        conn_key: Tuple,
        conn_info: ConnectionInfo,
    ) -> None:
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
        resolved = await self._resolve_target(host.decode(), port)
        remote_reader, remote_writer = await self._open_resolved_connection(resolved)
        remote_writer.write(http_data)
        await asyncio.wait_for(remote_writer.drain(), timeout=self.config.io_timeout)
        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()
        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    def _extract_sni_position(self, data):
        index = 0
        while index < len(data) - 8:
            if all(data[index + item] == 0x00 for item in [0, 1, 2, 4, 6, 7]):
                ext_len = data[index + 3]
                server_name_list_len = data[index + 5]
                server_name_len = data[index + 8]
                if ext_len - server_name_list_len == 2 and server_name_list_len - server_name_len == 3:
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
        try:
            head = await asyncio.wait_for(reader.read(5), timeout=self.config.io_timeout)
            data = await asyncio.wait_for(reader.read(2048), timeout=self.config.io_timeout)
        except Exception:
            self.logger.log_error(f"{host.decode()} : {traceback.format_exc()}")
            return

        should_fragment = True
        if not isinstance(self.blacklist_manager, NoBlacklistManager):
            should_fragment = self.blacklist_manager.is_blocked(conn_info.dst_domain)

        if not should_fragment:
            self.statistics.increment_total_connections()
            self.statistics.increment_allowed_connections()
            combined_data = head + data
            writer.write(combined_data)
            await asyncio.wait_for(writer.drain(), timeout=self.config.io_timeout)
            self.statistics.update_traffic(0, len(combined_data))
            conn_info.traffic_out += len(combined_data)
            return

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
                parts.append(bytes.fromhex("160304") + len(part_start).to_bytes(2, "big") + part_start)
                parts.append(bytes.fromhex("160304") + len(sni_data[:middle]).to_bytes(2, "big") + sni_data[:middle])
                parts.append(bytes.fromhex("160304") + len(sni_data[middle:]).to_bytes(2, "big") + sni_data[middle:])
                parts.append(bytes.fromhex("160304") + len(part_end).to_bytes(2, "big") + part_end)
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
                part_data = bytes.fromhex("160304") + chunk_len.to_bytes(2, "big") + data[:chunk_len]
                parts.append(part_data)
                data = data[chunk_len:]

        combined_parts = b"".join(parts)
        writer.write(combined_parts)
        await asyncio.wait_for(writer.drain(), timeout=self.config.io_timeout)
        self.statistics.update_traffic(0, len(combined_parts))
        conn_info.traffic_out += len(combined_parts)

    async def _setup_piping(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_key: Tuple,
    ) -> None:
        async with self.tasks_lock:
            self.tasks.extend(
                [
                    asyncio.create_task(self._pipe_data(client_reader, remote_writer, "out", conn_key)),
                    asyncio.create_task(self._pipe_data(remote_reader, client_writer, "in", conn_key)),
                ]
            )

    async def _pipe_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        conn_key: Tuple,
    ) -> None:
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
            self.logger.log_error(f"pipe_timeout direction={direction} conn_key={conn_key}")
        except Exception:
            domain = conn_info.dst_domain if conn_info else "unknown"
            self.logger.log_error(f"{domain} : {traceback.format_exc()}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            async with self.connections_lock:
                conn_info = self.active_connections.pop(conn_key, None)
                if conn_info:
                    self.logger.log_access(
                        f"{conn_info.start_time} {conn_info.src_ip} {conn_info.method} "
                        f"{conn_info.dst_domain} {conn_info.traffic_in} {conn_info.traffic_out}"
                    )

    async def _send_error_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        status_text: str,
        message: str,
    ) -> None:
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
        try:
            await self._send_error_response(writer, 500, "Internal Server Error", "Proxy internal error")
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
        status_map = {
            "nxdomain": (502, "Bad Gateway"),
            "temporary_failure": (502, "Bad Gateway"),
            "system_resolver_error": (502, "Bad Gateway"),
            "fallback_resolver_error": (502, "Bad Gateway"),
            "timeout": (504, "Gateway Timeout"),
        }
        status_code, status_text = status_map.get(error.reason_code, (502, "Bad Gateway"))
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
        dst_domain = conn_info.dst_domain if conn_info else error.host
        self.logger.log_error(
            "dns_error "
            f"host={error.host} port={error.port} reason={error.reason_code} "
            f"attempts={error.attempts} resolver_path={error.resolver_path} "
            f"resolver_used={error.resolver_used} exception_type={last_exception_type} "
            f"exception={last_exception_text} dst_domain={dst_domain}"
        )
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def cleanup_tasks(self) -> None:
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
        self.connection_handler = ConnectionHandler(config, blacklist_manager, statistics, logger)
        self.server = None
        self.update_check_task = None
        self.update_available = None
        self.update_event = asyncio.Event()
        logger.set_error_counter_callback(statistics.increment_error_connections)

    async def check_for_updates(self):
        if self.config.quiet:
            return None
        try:
            loop = asyncio.get_event_loop()

            def sync_check():
                try:
                    req = Request("https://gvcoder09.github.io/nodpi_site/api/v1/update_info.json")
                    with urlopen(req, timeout=3) as response:
                        if response.status == 200:
                            data = json.loads(response.read())
                            latest_version = data.get("nodpi", {}).get("latest_version", "")
                            if latest_version and latest_version != __version__:
                                return latest_version
                except (URLError, json.JSONDecodeError, Exception):
                    pass
                return None

            latest_version = await loop.run_in_executor(None, sync_check)
            if latest_version:
                self.update_available = latest_version
                self.update_event.set()
                return f"\033[93m[UPDATE]: Available new version: v{latest_version} \033[97m"
        except Exception:
            pass
        finally:
            self.update_event.set()
        return None

    async def print_banner(self) -> None:
        self.update_check_task = asyncio.create_task(self.check_for_updates())
        try:
            await asyncio.wait_for(self.update_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            if self.update_check_task and not self.update_check_task.done():
                self.update_check_task.cancel()
                try:
                    await self.update_check_task
                except asyncio.CancelledError:
                    pass

        self.logger.info("\033]0;NoDPI\007")
        if sys.platform == "win32":
            os.system("mode con: lines=33")

        console_width = os.get_terminal_size().columns if sys.stdout.isatty() else 80
        disclaimer = (
            "DISCLAIMER. The developer and/or supplier of this software "
            "shall not be liable for any loss or damage, including but "
            "not limited to direct, indirect, incidental, punitive or "
            "consequential damages arising out of the use of or inability "
            "to use this software, even if the developer or supplier has been "
            "advised of the possibility of such damages. The user is solely "
            "responsible for compliance with all applicable laws and regulations "
            "when using this software."
        )
        wrapped_text = textwrap.TextWrapper(width=70).wrap(disclaimer)
        left_padding = (console_width - 76) // 2
        self.logger.info("\n\n\n")
        self.logger.info("\033[91m" + " " * left_padding + "╔" + "═" * 72 + "╗" + "\033[0m")
        for line in wrapped_text:
            self.logger.info(
                "\033[91m" + " " * left_padding + "║ " + line.ljust(70) + " ║" + "\033[0m"
            )
        self.logger.info("\033[91m" + " " * left_padding + "╚" + "═" * 72 + "╝" + "\033[0m")
        time.sleep(1)

        update_message = None
        if self.update_check_task and self.update_check_task.done():
            try:
                update_message = self.update_check_task.result()
            except (asyncio.CancelledError, Exception):
                pass

        self.logger.info("\033[2J\033[H")
        self.logger.info(
            """
\033[92m  ██████   █████          ██████████   ███████████  █████
 ░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
  ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
  ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
  ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
  ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
  █████  ░░█████░░██████  ██████████   █████        █████
 ░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        """
        )
        self.logger.info(f"\033[92mVersion: {__version__}".center(50))
        self.logger.info("\033[97m" + "Enjoy watching! / Наслаждайтесь просмотром!".center(50))
        self.logger.info("\n")
        if update_message:
            self.logger.info(update_message)
        self.logger.info(
            f"\033[92m[INFO]:\033[97m Proxy is running on {self.config.host}:{self.config.port} "
            f"at {datetime.now().strftime('%H:%M on %Y-%m-%d')}"
        )
        self.logger.info(
            f"\033[92m[INFO]:\033[97m The selected fragmentation method: {self.config.fragment_method}"
        )
        self.logger.info(
            f"\033[92m[INFO]:\033[97m Connection timeout: {self.config.connect_timeout}s, "
            f"I/O timeout: {self.config.io_timeout}s, DNS timeout: {self.config.dns_tcp_timeout}s"
        )
        self.logger.info("")
        if isinstance(self.blacklist_manager, NoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Blacklist is disabled. All domains will be subject to unblocking."
            )
        elif isinstance(self.blacklist_manager, AutoBlacklistManager):
            self.logger.info("\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Blacklist contains {len(self.blacklist_manager.blocked)} domains"
            )
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Path to blacklist: '{os.path.normpath(self.config.blacklist_file)}'"
            )
        self.logger.info("")
        if self.config.log_error_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Error logging is enabled. Path to error log: '{self.config.log_error_file}'"
            )
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Error logging is disabled")
        if self.config.log_access_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Access logging is enabled. Path to access log: '{self.config.log_access_file}'"
            )
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Access logging is disabled")
        self.logger.info("")
        self.logger.info("\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice")
        self.logger.info("")

    async def display_stats(self) -> None:
        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                print(self.statistics.get_stats_display())
                print("\033[5A", end="")

    async def run(self) -> None:
        if not self.config.quiet:
            await self.print_banner()
        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.host,
                self.config.port,
            )
        except OSError:
            self.logger.error(
                f"\033[91m[ERROR]: Failed to start proxy on this address "
                f"({self.config.host}:{self.config.port}). It looks like the port is already in use\033[0m"
            )
            sys.exit(1)

        if not self.config.quiet:
            asyncio.create_task(self.display_stats())
        asyncio.create_task(self.connection_handler.cleanup_tasks())
        await self.server.serve_forever()

    async def shutdown(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in self.connection_handler.tasks:
            task.cancel()
