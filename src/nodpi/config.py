"""Configuration loading and argument parsing."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class ProxyConfig:
    """Configuration container for proxy settings."""

    host: str = "127.0.0.1"
    port: int = 8881
    out_host: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    blacklist_file: str = "blacklist.txt"
    fragment_method: str = "random"
    domain_matching: str = "strict"
    log_access_file: Optional[str] = None
    log_error_file: Optional[str] = None
    no_blacklist: bool = False
    auto_blacklist: bool = False
    quiet: bool = False
    start_in_tray: bool = False
    dns_retry_attempts: int = 3
    dns_retry_delay: float = 0.2
    dns_resolvers: List[str] = None
    dns_tcp_timeout: float = 2.0
    dns_system_timeout: float = 2.0
    dns_prefer_ipv4: bool = True
    connect_timeout: float = 5.0
    io_timeout: float = 30.0
    read_chunk_size: int = 1500

    def __post_init__(self) -> None:
        if self.dns_resolvers is None:
            self.dns_resolvers = ["8.8.8.8", "1.1.1.1"]


class ConfigLoader:
    """Loads configuration from command line arguments, env, and JSON."""

    ENV_PREFIX = "NODPI_"
    DEFAULT_CONFIG_NAME = "nodpi.json"

    @staticmethod
    def create_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser()
        parser.add_argument("--config", help="Path to JSON config file")
        parser.add_argument("--host", default=None, help="Proxy host")
        parser.add_argument("--port", type=int, default=None, help="Proxy port")
        parser.add_argument("--out-host", default=None, help="Outgoing proxy host")

        blacklist_group = parser.add_mutually_exclusive_group()
        blacklist_group.add_argument("--blacklist", default=None, help="Path to blacklist file")
        blacklist_group.add_argument(
            "--no-blacklist",
            action="store_true",
            help="Use fragmentation for all domains",
        )
        blacklist_group.add_argument(
            "--autoblacklist",
            action="store_true",
            help="Automatic detection of blocked domains",
        )

        parser.add_argument(
            "--fragment-method",
            default=None,
            choices=["random", "sni"],
            help="Fragmentation method (random by default)",
        )
        parser.add_argument(
            "--domain-matching",
            default=None,
            choices=["loose", "strict"],
            help="Domain matching mode (strict by default)",
        )
        parser.add_argument("--auth-username", default=None, help="Proxy auth username")
        parser.add_argument("--auth-password", default=None, help="Proxy auth password")
        parser.add_argument("--log-access", default=None, help="Path to access log")
        parser.add_argument("--log-error", default=None, help="Path to error log")
        parser.add_argument(
            "--dns-retries",
            type=int,
            default=None,
            help="Number of system DNS resolve retries before fallback",
        )
        parser.add_argument(
            "--dns-retry-delay",
            type=float,
            default=None,
            help="Delay between DNS retries in seconds",
        )
        parser.add_argument(
            "--dns-resolver",
            action="append",
            default=None,
            help="Fallback DNS-over-TCP resolver IP address (can be used multiple times)",
        )
        parser.add_argument(
            "--dns-timeout",
            type=float,
            default=None,
            help="Timeout in seconds for DNS operations",
        )
        parser.add_argument(
            "--connect-timeout",
            type=float,
            default=None,
            help="Timeout in seconds for outbound TCP connect",
        )
        parser.add_argument(
            "--io-timeout",
            type=float,
            default=None,
            help="Idle timeout in seconds for socket reads/writes",
        )
        parser.add_argument(
            "--read-chunk-size",
            type=int,
            default=None,
            help="Socket read chunk size",
        )
        parser.add_argument("-q", "--quiet", action="store_true", help="Remove UI output")
        parser.add_argument(
            "--start-in-tray",
            action="store_true",
            help="Start minimized to tray (Windows only)",
        )

        autostart_group = parser.add_mutually_exclusive_group()
        autostart_group.add_argument(
            "--install",
            action="store_true",
            help="Add proxy to Windows/Linux autostart (only for executable version)",
        )
        autostart_group.add_argument(
            "--uninstall",
            action="store_true",
            help="Remove proxy from Windows/Linux autostart (only for executable version)",
        )
        return parser

    @classmethod
    def load(cls, args: argparse.Namespace) -> ProxyConfig:
        config = ProxyConfig()
        config_path = cls._resolve_config_path(getattr(args, "config", None))
        for key, value in cls._load_json_config(config_path).items():
            cls._assign(config, key, value)

        for key, value in cls._load_env_config().items():
            cls._assign(config, key, value)

        cli_values = cls._extract_cli_values(args)
        for key, value in cli_values.items():
            cls._assign(config, key, value)

        if config.no_blacklist:
            config.auto_blacklist = False
        if config.auto_blacklist:
            config.no_blacklist = False
        return config

    @classmethod
    def _resolve_config_path(cls, explicit_path: Optional[str]) -> Optional[Path]:
        if explicit_path:
            return Path(explicit_path).expanduser().resolve()

        env_path = os.environ.get(f"{cls.ENV_PREFIX}CONFIG")
        if env_path:
            return Path(env_path).expanduser().resolve()

        for candidate in cls._default_config_candidates():
            if candidate.is_file():
                return candidate
        return None

    @classmethod
    def _default_config_candidates(cls) -> Sequence[Path]:
        candidates = [Path.cwd() / cls.DEFAULT_CONFIG_NAME]

        if getattr(sys, "frozen", False):
            candidates.append(Path(sys.executable).resolve().parent / cls.DEFAULT_CONFIG_NAME)
        else:
            candidates.append(Path(__file__).resolve().parents[2] / cls.DEFAULT_CONFIG_NAME)

        unique_candidates = []
        seen = set()
        for candidate in candidates:
            resolved_candidate = candidate.resolve()
            if resolved_candidate in seen:
                continue
            seen.add(resolved_candidate)
            unique_candidates.append(resolved_candidate)
        return unique_candidates

    @classmethod
    def _load_json_config(cls, path: Optional[Path]) -> Dict[str, Any]:
        if not path:
            return {}

        with path.open("r", encoding="utf-8") as file:
            raw = json.load(file)

        if not isinstance(raw, dict):
            raise ValueError("Config file must contain a JSON object")
        return raw

    @classmethod
    def _load_env_config(cls) -> Dict[str, Any]:
        config: Dict[str, Any] = {}
        for field in fields(ProxyConfig):
            env_key = cls.ENV_PREFIX + field.name.upper()
            if env_key not in os.environ:
                continue
            config[field.name] = cls._coerce_value(field.name, os.environ[env_key])
        return config

    @classmethod
    def _extract_cli_values(cls, args: argparse.Namespace) -> Dict[str, Any]:
        mapping = {
            "host": args.host,
            "port": args.port,
            "out_host": args.out_host,
            "username": args.auth_username,
            "password": args.auth_password,
            "blacklist_file": args.blacklist,
            "fragment_method": args.fragment_method,
            "domain_matching": args.domain_matching,
            "log_access_file": args.log_access,
            "log_error_file": args.log_error,
            "dns_retry_attempts": args.dns_retries,
            "dns_retry_delay": args.dns_retry_delay,
            "dns_resolvers": args.dns_resolver,
            "dns_tcp_timeout": args.dns_timeout,
            "dns_system_timeout": args.dns_timeout,
            "connect_timeout": args.connect_timeout,
            "io_timeout": args.io_timeout,
            "read_chunk_size": args.read_chunk_size,
        }

        if args.no_blacklist:
            mapping["no_blacklist"] = True
            mapping["auto_blacklist"] = False
        if args.autoblacklist:
            mapping["auto_blacklist"] = True
            mapping["no_blacklist"] = False
        if args.quiet:
            mapping["quiet"] = True
        if args.start_in_tray:
            mapping["start_in_tray"] = True

        return {key: value for key, value in mapping.items() if value is not None}

    @classmethod
    def _assign(cls, config: ProxyConfig, key: str, value: Any) -> None:
        if not hasattr(config, key):
            return
        setattr(config, key, cls._coerce_value(key, value))

    @staticmethod
    def _coerce_value(key: str, value: Any) -> Any:
        if key in {
            "port",
            "dns_retry_attempts",
            "read_chunk_size",
        }:
            return int(value)
        if key in {
            "dns_retry_delay",
            "dns_tcp_timeout",
            "dns_system_timeout",
            "connect_timeout",
            "io_timeout",
        }:
            return float(value)
        if key in {
            "no_blacklist",
            "auto_blacklist",
            "quiet",
            "start_in_tray",
            "dns_prefer_ipv4",
        }:
            if isinstance(value, bool):
                return value
            return str(value).lower() in {"1", "true", "yes", "on"}
        if key == "dns_resolvers":
            if isinstance(value, list):
                return [str(item) for item in value]
            return [item.strip() for item in str(value).split(",") if item.strip()]
        return value
