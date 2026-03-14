#!/usr/bin/env python3

"""Compatibility entrypoint for NoDPI."""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from nodpi.app import ProxyApplication, main
from nodpi.blacklists import (
    AutoBlacklistManager,
    BlacklistManagerFactory,
    FileBlacklistManager,
    NoBlacklistManager,
)
from nodpi.config import ConfigLoader, ProxyConfig
from nodpi.contracts import (
    IAutostartManager,
    IBlacklistManager,
    IConnectionHandler,
    ILogger,
    IStatistics,
)
from nodpi.logging_utils import ProxyLogger
from nodpi.models import ConnectionInfo, DnsResolveError, ResolvedTarget
from nodpi.platform import LinuxAutostartManager, WindowsAutostartManager, WindowsTrayIcon
from nodpi.proxy import ConnectionHandler, ProxyServer
from nodpi.statistics import Statistics
from nodpi.version import __version__

__all__ = [
    "AutoBlacklistManager",
    "BlacklistManagerFactory",
    "ConfigLoader",
    "ConnectionHandler",
    "ConnectionInfo",
    "DnsResolveError",
    "FileBlacklistManager",
    "IAutostartManager",
    "IBlacklistManager",
    "IConnectionHandler",
    "ILogger",
    "IStatistics",
    "LinuxAutostartManager",
    "NoBlacklistManager",
    "ProxyApplication",
    "ProxyConfig",
    "ProxyLogger",
    "ProxyServer",
    "ResolvedTarget",
    "Statistics",
    "WindowsAutostartManager",
    "WindowsTrayIcon",
    "__version__",
    "main",
]


if __name__ == "__main__":
    main()
