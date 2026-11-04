import argparse
import io
import os
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from vidaa import cli
from vidaa.client import VidaaTV
from vidaa.config import loader as config_loader
from vidaa.config.storage import TokenStorage
from vidaa.protocol import AuthMethod, get_auth_method_order


class RegressionTests(unittest.TestCase):
    def tearDown(self):
        config_loader._cached_config = None
        config_loader._cached_path = None
        config_loader._save_path = None
        config_loader._cached_search_paths = None

    def test_config_path_precedence_and_cwd_independence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            default_path = root / ".config" / "vidaa-control" / "config.yaml"
            legacy_path = root / "config.yaml"
            env_path = root / "custom" / "config.yaml"
            other_cwd = root / "elsewhere"
            other_cwd.mkdir()

            default_path.parent.mkdir(parents=True)
            env_path.parent.mkdir(parents=True)
            default_path.write_text("default_tv: default\n")
            legacy_path.write_text("default_tv: legacy\n")
            env_path.write_text("default_tv: env\n")

            old_cwd = Path.cwd()
            try:
                os.chdir(other_cwd)
                with ExitStack() as stack:
                    stack.enter_context(patch.object(config_loader, "DEFAULT_CONFIG_PATH", default_path))
                    stack.enter_context(patch.object(config_loader, "LEGACY_HOME_CONFIG_PATH", legacy_path))
                    stack.enter_context(patch.dict(os.environ, {"VIDAA_CONFIG_PATH": str(env_path)}, clear=True))
                    config = config_loader.load_config(use_cache=False)
                    self.assertEqual(config["default_tv"], "env")
                    self.assertEqual(config_loader.get_config_path(), env_path)

                    # Changing the environment path invalidates the cache.
                    os.environ.pop("VIDAA_CONFIG_PATH")
                    config = config_loader.load_config()
                    self.assertEqual(config["default_tv"], "default")
                    self.assertEqual(config_loader.get_config_path(), default_path)
            finally:
                os.chdir(old_cwd)

    def test_legacy_home_config_is_used_without_moving_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            default_path = root / ".config" / "vidaa-control" / "config.yaml"
            legacy_path = root / "config.yaml"
            legacy_path.write_text("default_tv: legacy\n")

            with ExitStack() as stack:
                stack.enter_context(patch.object(config_loader, "DEFAULT_CONFIG_PATH", default_path))
                stack.enter_context(patch.object(config_loader, "LEGACY_HOME_CONFIG_PATH", legacy_path))
                stack.enter_context(patch.dict(os.environ, {}, clear=True))
                config = config_loader.load_config(use_cache=False)
                config["default_tv"] = "updated-legacy"
                self.assertTrue(config_loader.save_config(config))

            self.assertFalse(default_path.exists())
            self.assertIn("updated-legacy", legacy_path.read_text())

    def test_missing_config_is_saved_to_new_default_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            default_path = root / ".config" / "vidaa-control" / "config.yaml"
            legacy_path = root / "config.yaml"

            with ExitStack() as stack:
                stack.enter_context(patch.object(config_loader, "DEFAULT_CONFIG_PATH", default_path))
                stack.enter_context(patch.object(config_loader, "LEGACY_HOME_CONFIG_PATH", legacy_path))
                stack.enter_context(patch.dict(os.environ, {}, clear=True))
                config = config_loader.load_config(use_cache=False)
                self.assertTrue(config_loader.save_config(config))

            self.assertTrue(default_path.exists())
            self.assertFalse(legacy_path.exists())

    def test_set_source_publishes_canonical_name(self):
        tv = VidaaTV.__new__(VidaaTV)
        tv.client_id = "test-client"
        tv._connected = True
        published = []
        tv._publish = lambda topic, payload: published.append((topic, payload)) or True

        self.assertTrue(tv.set_source("hdmi1"))
        self.assertEqual(published[0][1], {"sourceid": "HDMI1"})

    def test_config_show_and_list_accept_structured_tv_entries(self):
        tvs = [{
            "device_id": "aabbccddeeff",
            "host": "192.0.2.10",
            "port": 36669,
            "alias": "living-room",
            "is_default": True,
        }]

        with patch.object(cli, "list_tvs", return_value=tvs):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.cmd_config(argparse.Namespace(action="show")), 0)
                self.assertEqual(cli.cmd_config(argparse.Namespace(action="list")), 0)

        self.assertIn("aabbccddeeff", output.getvalue())
        self.assertIn("living-room", output.getvalue())
        self.assertIn("default", output.getvalue())

    def test_create_tv_client_prefers_configured_mac_and_auth_settings(self):
        tv_config = {
            "host": "192.0.2.10",
            "mac": "AA:BB:CC:DD:EE:FF",
            "device_id": "001122334455",
            "use_dynamic_auth": True,
            "auth_method": "middle",
            "auto_detect_protocol": False,
        }

        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, "get_tv_config", return_value=tv_config))
            stack.enter_context(patch.object(cli, "resolve_tv_id", return_value="001122334455"))
            get_mac = stack.enter_context(patch.object(cli, "get_mac_from_ip"))
            stack.enter_context(patch.object(cli, "VidaaTV", side_effect=lambda **kwargs: kwargs))
            with self.assertLogs(cli._LOGGER, level="INFO") as logs:
                client_args = cli.create_tv_client(tv_id="living-room")

        get_mac.assert_not_called()
        self.assertEqual(client_args["mac_address"], "AA:BB:CC:DD:EE:FF")
        self.assertTrue(client_args["use_dynamic_auth"])
        self.assertIs(client_args["auth_method"], AuthMethod.MIDDLE)
        self.assertFalse(client_args["auto_detect_protocol"])
        self.assertIn("dynamic/middle", " ".join(logs.output))

    def test_create_tv_client_keeps_explicit_dynamic_auth_without_mac(self):
        tv_config = {
            "host": "192.0.2.10",
            "use_dynamic_auth": True,
            "auto_detect_protocol": False,
        }

        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, "get_tv_config", return_value=tv_config))
            stack.enter_context(patch.object(cli, "resolve_tv_id", return_value=None))
            stack.enter_context(patch.object(cli, "get_mac_from_ip", return_value=None))
            stack.enter_context(patch.object(cli, "VidaaTV", side_effect=lambda **kwargs: kwargs))
            client_args = cli.create_tv_client(tv_id="legacy-name")

        self.assertTrue(client_args["use_dynamic_auth"])
        self.assertIs(client_args["auth_method"], AuthMethod.MODERN)
        self.assertFalse(client_args["auto_detect_protocol"])

    def test_create_tv_client_supports_explicit_static_auth(self):
        tv_config = {
            "host": "192.0.2.10",
            "mac": "AA:BB:CC:DD:EE:FF",
            "use_dynamic_auth": False,
            "auth_method": "modern",
        }

        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, "get_tv_config", return_value=tv_config))
            stack.enter_context(patch.object(cli, "resolve_tv_id", return_value=None))
            get_mac = stack.enter_context(patch.object(cli, "get_mac_from_ip"))
            stack.enter_context(patch.object(cli, "VidaaTV", side_effect=lambda **kwargs: kwargs))
            client_args = cli.create_tv_client(tv_id="old-tv")

        get_mac.assert_not_called()
        self.assertFalse(client_args["use_dynamic_auth"])
        self.assertIsNone(client_args["auth_method"])

    def test_ip_override_reuses_matching_configured_mac(self):
        configured_tv = {
            "device_id": "001122334455",
            "host": "192.0.2.10",
            "mac": "AA:BB:CC:DD:EE:FF",
            "use_dynamic_auth": True,
            "auto_detect_protocol": False,
            "auth_method": "legacy",
        }

        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, "list_tvs", return_value=[configured_tv]))
            get_mac = stack.enter_context(patch.object(cli, "get_mac_from_ip"))
            stack.enter_context(patch.object(cli, "VidaaTV", side_effect=lambda **kwargs: kwargs))
            client_args = cli.create_tv_client(ip="192.0.2.10")

        get_mac.assert_not_called()
        self.assertEqual(client_args["mac_address"], "AA:BB:CC:DD:EE:FF")
        self.assertIs(client_args["auth_method"], AuthMethod.LEGACY)

    def test_protocol_specific_auth_method_is_first(self):
        self.assertIs(get_auth_method_order(2500)[0], AuthMethod.LEGACY)
        self.assertIs(get_auth_method_order(3100)[0], AuthMethod.MIDDLE)
        self.assertIs(get_auth_method_order(3290)[0], AuthMethod.MODERN)

    def test_token_lookup_and_refresh_preserve_refresh_token(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = TokenStorage(Path(directory) / "tokens.json")
            storage.save_token(
                device_id="aabbccddeeff",
                host="192.0.2.10",
                access_token="old-access",
                refresh_token="refresh-token",
            )
            old_expiry = storage.get_token(
                host="192.0.2.10"
            )["refresh_token_expires_at"]

            storage.save_token(
                device_id="aabbccddeeff",
                host="192.0.2.10",
                access_token="new-access",
                refresh_token=None,
            )

            saved = storage.get_token(host="192.0.2.10")
            self.assertEqual(saved["access_token"], "new-access")
            self.assertEqual(saved["refresh_token"], "refresh-token")
            self.assertEqual(saved["refresh_token_expires_at"], old_expiry)

    def test_authenticate_waits_until_token_is_received(self):
        tv = VidaaTV.__new__(VidaaTV)
        tv.client_id = "test-client"
        tv._auth_event = threading.Event()
        tv._authenticated = False
        tv._access_token = None
        tv._publish = lambda topic, payload: True

        def issue_token():
            time.sleep(0.01)
            tv._authenticated = True
            tv._auth_event.set()
            time.sleep(0.01)
            tv._access_token = "access-token"
            tv._auth_event.set()

        thread = threading.Thread(target=issue_token)
        thread.start()
        try:
            self.assertTrue(tv.authenticate("1234", timeout=1))
        finally:
            thread.join()

    def test_default_token_path_is_stable(self):
        self.assertEqual(TokenStorage.DEFAULT_STORAGE_PATH.name, "tokens.json")
        self.assertEqual(TokenStorage.DEFAULT_STORAGE_PATH.parent.name, "vidaa")


if __name__ == "__main__":
    unittest.main()
