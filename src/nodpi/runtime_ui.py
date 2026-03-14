"""Runtime UI and update-check helpers."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import textwrap
import time

from datetime import datetime
from urllib.error import URLError
from urllib.request import Request, urlopen

from .blacklists import AutoBlacklistManager, NoBlacklistManager
from .config import ProxyConfig
from .contracts import IBlacklistManager, ILogger, IStatistics
from .version import __version__


class ProxyRuntimeUI:
    """Owns update checks, startup banner, and live statistics rendering."""

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
        self.update_check_task = None
        self.update_available = None
        self.update_event = asyncio.Event()

    async def check_for_updates(self):
        """Check if a newer version is available."""

        if self.config.quiet:
            return None

        try:
            loop = asyncio.get_event_loop()

            def sync_check():
                try:
                    req = Request(
                        "https://gvcoder09.github.io/nodpi_site/api/v1/update_info.json"
                    )
                    with urlopen(req, timeout=3) as response:
                        if response.status == 200:
                            data = json.loads(response.read())
                            latest_version = data.get("nodpi", {}).get(
                                "latest_version", ""
                            )
                            if latest_version and latest_version != __version__:
                                return latest_version
                except (URLError, json.JSONDecodeError, Exception):
                    pass
                return None

            latest_version = await loop.run_in_executor(None, sync_check)
            if latest_version:
                self.update_available = latest_version
                self.update_event.set()
                return (
                    f"\033[93m[UPDATE]: Available new version: "
                    f"v{latest_version} \033[97m"
                )
        except Exception:
            pass
        finally:
            self.update_event.set()
        return None

    async def print_banner(self) -> None:
        """Print the startup banner and current runtime configuration."""

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
        self.logger.info(
            "\033[91m" + " " * left_padding + "╔" + "═" * 72 + "╗" + "\033[0m"
        )
        for line in wrapped_text:
            self.logger.info(
                "\033[91m"
                + " " * left_padding
                + "║ "
                + line.ljust(70)
                + " ║"
                + "\033[0m"
            )
        self.logger.info(
            "\033[91m" + " " * left_padding + "╚" + "═" * 72 + "╝" + "\033[0m"
        )
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
        self.logger.info(
            "\033[97m" + "Enjoy watching! / Наслаждайтесь просмотром!".center(50)
        )
        self.logger.info("\n")
        if update_message:
            self.logger.info(update_message)
        self.logger.info(
            f"\033[92m[INFO]:\033[97m Proxy is running on "
            f"{self.config.host}:{self.config.port} at "
            f"{datetime.now().strftime('%H:%M on %Y-%m-%d')}"
        )
        self.logger.info(
            f"\033[92m[INFO]:\033[97m The selected fragmentation method: "
            f"{self.config.fragment_method}"
        )
        self.logger.info(
            f"\033[92m[INFO]:\033[97m Connection timeout: "
            f"{self.config.connect_timeout}s, I/O timeout: "
            f"{self.config.io_timeout}s, DNS timeout: "
            f"{self.config.dns_tcp_timeout}s"
        )
        self.logger.info("")
        if isinstance(self.blacklist_manager, NoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Blacklist is disabled. "
                "All domains will be subject to unblocking."
            )
        elif isinstance(self.blacklist_manager, AutoBlacklistManager):
            self.logger.info("\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Blacklist contains "
                f"{len(self.blacklist_manager.blocked)} domains"
            )
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Path to blacklist: "
                f"'{os.path.normpath(self.config.blacklist_file)}'"
            )
        self.logger.info("")
        if self.config.log_error_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Error logging is enabled. "
                f"Path to error log: '{self.config.log_error_file}'"
            )
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Error logging is disabled")
        if self.config.log_access_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Access logging is enabled. "
                f"Path to access log: '{self.config.log_access_file}'"
            )
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Access logging is disabled")
        self.logger.info("")
        self.logger.info(
            "\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice"
        )
        self.logger.info("")

    async def display_stats(self) -> None:
        """Render live statistics until cancelled."""

        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                print(self.statistics.get_stats_display())
                print("\033[5A", end="")
