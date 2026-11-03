import argparse
import io
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from vidaa import cli
from vidaa.client import VidaaTV
from vidaa.config.storage import TokenStorage
from vidaa.protocol import AuthMethod, get_auth_method_order


class RegressionTests(unittest.TestCase):
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
