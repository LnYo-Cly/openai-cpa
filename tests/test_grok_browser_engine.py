import os
import sys
import types
import unittest
from unittest.mock import patch

from utils.grok_auth import browser_pool


class _Manager:
    def __init__(self, playwright):
        self.playwright = playwright
        self.stopped = False

    def start(self):
        return self.playwright

    def stop(self):
        self.stopped = True


class _Chromium:
    def __init__(self):
        self.kwargs = None

    def launch(self, **kwargs):
        self.kwargs = kwargs
        return object()


class _Camoufox:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.closed = False

    def __enter__(self):
        return object()

    def __exit__(self, *_args):
        self.closed = True


class GrokBrowserEngineTests(unittest.TestCase):
    def test_default_engine_keeps_camoufox_when_chromium_is_installed(self):
        manager = _Camoufox(headless=True)
        fake_api = types.SimpleNamespace(Camoufox=lambda **kwargs: manager)
        with patch.dict(
            os.environ,
            {"GROK_BROWSER_ENGINE": ""},
            clear=False,
        ), patch.dict(sys.modules, {"camoufox.sync_api": fake_api}), patch.object(
            browser_pool.shutil, "which", return_value="/usr/bin/chromium"
        ):
            actual_manager, browser = browser_pool._launch_browser(True)
            browser_pool._close_browser(actual_manager, browser)

        self.assertIs(actual_manager, manager)
        self.assertTrue(manager.closed)
        self.assertTrue(manager.kwargs["headless"])

    def test_chromium_engine_uses_system_browser_and_is_closable(self):
        chromium = _Chromium()
        manager = _Manager(types.SimpleNamespace(chromium=chromium))
        fake_api = types.SimpleNamespace(sync_playwright=lambda: manager)
        with patch.dict(
            os.environ,
            {"GROK_BROWSER_ENGINE": "chromium"},
            clear=False,
        ), patch.dict(sys.modules, {"playwright.sync_api": fake_api}), patch.object(
            browser_pool.shutil, "which", return_value="/usr/bin/chromium"
        ):
            actual_manager, browser = browser_pool._launch_browser(True)
            browser_pool._close_browser(actual_manager, browser)

        self.assertIs(actual_manager, manager)
        self.assertTrue(manager.stopped)
        self.assertEqual(chromium.kwargs["executable_path"], "/usr/bin/chromium")
        self.assertTrue(chromium.kwargs["headless"])
        self.assertIn("--no-sandbox", chromium.kwargs["args"])


if __name__ == "__main__":
    unittest.main()
