"""Application bootstrap."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from .blacklists import BlacklistManagerFactory
from .config import ConfigLoader
from .logging_utils import ProxyLogger
from .platform import LinuxAutostartManager, WindowsAutostartManager, WindowsTrayIcon
from .proxy import ProxyServer
from .statistics import Statistics
from .version import __version__


class ProxyApplication:
    """Main application class."""

    @staticmethod
    def parse_args():
        return ConfigLoader.create_parser().parse_args()

    @classmethod
    async def run(cls):
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)
        args = cls.parse_args()

        if args.install or args.uninstall:
            if getattr(sys, "frozen", False):
                if args.install:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("install")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("install")
                elif args.uninstall:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("uninstall")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("uninstall")
                sys.exit(0)
            else:
                print("\033[91m[ERROR]: Autostart works only in executable version\033[0m")
                sys.exit(1)

        config = ConfigLoader.load(args)
        logger = ProxyLogger(config.log_access_file, config.log_error_file, config.quiet)
        blacklist_manager = BlacklistManagerFactory.create(config, logger)
        statistics = Statistics()
        logger.set_error_counter_callback(statistics.increment_error_connections)

        if sys.platform == "win32" and not config.quiet and WindowsTrayIcon is not None:
            tray = WindowsTrayIcon(tooltip=f"NoDPI v{__version__}")
            tray.start()
            if config.start_in_tray:
                tray.hide_to_tray()

        proxy = ProxyServer(config, blacklist_manager, statistics, logger)
        try:
            await proxy.run()
        except asyncio.CancelledError:
            await proxy.shutdown()
            logger.info("\n" * 6 + "\033[92m[INFO]:\033[97m Shutting down proxy...")
            try:
                if sys.platform == "win32":
                    os.system("mode con: lines=3000")
                sys.exit(0)
            except asyncio.CancelledError:
                pass


def main() -> None:
    try:
        asyncio.run(ProxyApplication.run())
    except KeyboardInterrupt:
        pass
