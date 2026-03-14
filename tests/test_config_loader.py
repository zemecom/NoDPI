import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from nodpi.config import ConfigLoader


class ConfigLoaderTests(unittest.TestCase):
    def test_default_config_file_is_loaded_automatically(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "nodpi.json"
            config_path.write_text(
                json.dumps(
                    {
                        "host": "127.0.0.9",
                        "port": 8899,
                        "dns_resolvers": ["8.8.4.4"],
                    }
                ),
                encoding="utf-8",
            )

            parser = ConfigLoader.create_parser()
            args = parser.parse_args([])

            with patch.object(
                ConfigLoader,
                "_default_config_candidates",
                return_value=[config_path],
            ):
                config = ConfigLoader.load(args)

        self.assertEqual(config.host, "127.0.0.9")
        self.assertEqual(config.port, 8899)
        self.assertEqual(config.dns_resolvers, ["8.8.4.4"])

    def test_json_env_and_cli_are_merged_in_order(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "nodpi.json"
            config_path.write_text(
                json.dumps(
                    {
                        "host": "0.0.0.0",
                        "port": 9000,
                        "dns_resolvers": ["9.9.9.9"],
                        "connect_timeout": 7.0,
                    }
                ),
                encoding="utf-8",
            )

            parser = ConfigLoader.create_parser()
            args = parser.parse_args(
                [
                    "--config",
                    str(config_path),
                    "--port",
                    "8889",
                    "--dns-resolver",
                    "8.8.8.8",
                    "--dns-resolver",
                    "1.1.1.1",
                ]
            )

            with patch.dict(
                os.environ,
                {
                    "NODPI_HOST": "127.0.0.2",
                    "NODPI_IO_TIMEOUT": "45",
                },
                clear=False,
            ):
                config = ConfigLoader.load(args)

        self.assertEqual(config.host, "127.0.0.2")
        self.assertEqual(config.port, 8889)
        self.assertEqual(config.dns_resolvers, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(config.connect_timeout, 7.0)
        self.assertEqual(config.io_timeout, 45.0)

    def test_boolean_env_values_are_coerced(self):
        parser = ConfigLoader.create_parser()
        args = parser.parse_args([])
        with patch.dict(
            os.environ,
            {
                "NODPI_QUIET": "true",
                "NODPI_NO_BLACKLIST": "1",
            },
            clear=False,
        ):
            config = ConfigLoader.load(args)

        self.assertTrue(config.quiet)
        self.assertTrue(config.no_blacklist)


if __name__ == "__main__":
    unittest.main()
