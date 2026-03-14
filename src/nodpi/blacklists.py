"""Blacklist managers."""

from __future__ import annotations

import os
import ssl
import sys

from urllib.error import URLError
from urllib.request import Request, urlopen

from .config import ProxyConfig
from .contracts import IBlacklistManager, ILogger


class FileBlacklistManager(IBlacklistManager):
    """Blacklist manager that uses file-based blacklist."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.blacklist_file = self.config.blacklist_file
        self.blocked = []
        self.load_blacklist()

    def load_blacklist(self) -> None:
        if not os.path.exists(self.blacklist_file):
            raise FileNotFoundError(f"File {self.blacklist_file} not found")

        with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if len(line.strip()) < 2 or line.strip()[0] == "#":
                    continue
                self.blocked.append(line.strip().lower().replace("www.", ""))

    def is_blocked(self, domain: str) -> bool:
        domain = domain.replace("www.", "")
        if self.config.domain_matching == "loose":
            for blocked_domain in self.blocked:
                if blocked_domain in domain:
                    return True
        if domain in self.blocked:
            return True
        parts = domain.split(".")
        for index in range(1, len(parts)):
            parent_domain = ".".join(parts[index:])
            if parent_domain in self.blocked:
                return True
        return False

    async def check_domain(self, domain: bytes) -> None:
        return None


class AutoBlacklistManager(IBlacklistManager):
    """Blacklist manager that automatically detects blocked domains."""

    def __init__(self, config: ProxyConfig):
        self.blacklist_file = config.blacklist_file
        self.blocked = []
        self.whitelist = []

    def is_blocked(self, domain: str) -> bool:
        return domain in self.blocked

    async def check_domain(self, domain: bytes) -> None:
        decoded_domain = domain.decode()
        if decoded_domain in self.blocked or decoded_domain in self.whitelist:
            return

        try:
            request = Request(
                f"https://{decoded_domain}", headers={"User-Agent": "Mozilla/5.0"}
            )
            context = ssl._create_unverified_context()
            with urlopen(request, timeout=4, context=context):
                self.whitelist.append(decoded_domain)
        except URLError as error:
            reason = str(error.reason)
            if "handshake operation timed out" in reason:
                self.blocked.append(decoded_domain)
                with open(self.blacklist_file, "a", encoding="utf-8") as file:
                    file.write(decoded_domain + "\n")


class NoBlacklistManager(IBlacklistManager):
    """Blacklist manager that doesn't block anything."""

    def is_blocked(self, domain: str) -> bool:
        return True

    async def check_domain(self, domain: bytes) -> None:
        return None


class BlacklistManagerFactory:
    """Factory for creating blacklist managers."""

    @staticmethod
    def create(config: ProxyConfig, logger: ILogger) -> IBlacklistManager:
        if config.no_blacklist:
            return NoBlacklistManager()
        if config.auto_blacklist:
            return AutoBlacklistManager(config)
        try:
            return FileBlacklistManager(config)
        except FileNotFoundError as error:
            logger.error(f"\033[91m[ERROR]: {error}\033[0m")
            sys.exit(1)
