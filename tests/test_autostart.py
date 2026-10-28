from __future__ import annotations

import os
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ip_guard.autostart import install_autostart, is_autostart_installed, remove_autostart


class AutostartTests(unittest.TestCase):
    def test_windows_source_mode_uses_pythonw_and_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / "venv" / "Scripts" / "python.exe"
            pythonw = python.with_name("pythonw.exe")
            python.parent.mkdir(parents=True)
            python.touch()
            pythonw.touch()
            config = root / "config.json"

            with (
                patch("ip_guard.autostart.platform.system", return_value="Windows"),
                patch.dict(os.environ, {"APPDATA": str(root / "AppData")}),
                patch.object(sys, "executable", str(python)),
            ):
                destination = install_autostart(config)
                content = destination.read_text(encoding="utf-8")
                self.assertIn(str(pythonw), content)
                self.assertIn("-m ip_guard", content)
                self.assertTrue(is_autostart_installed())
                self.assertEqual(destination, remove_autostart())
                self.assertFalse(destination.exists())

    def test_windows_frozen_mode_uses_permanent_executable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "dist" / "KiroIPGuard" / "KiroIPGuard.exe"
            executable.parent.mkdir(parents=True)
            executable.touch()
            config = root / "config.json"

            with (
                patch("ip_guard.autostart.platform.system", return_value="Windows"),
                patch.dict(os.environ, {"APPDATA": str(root / "AppData")}),
                patch.object(sys, "executable", str(executable)),
                patch.object(sys, "frozen", True, create=True),
            ):
                destination = install_autostart(config)
                content = destination.read_text(encoding="utf-8")
                self.assertIn(str(executable), content)
                self.assertIn(f'cd /d "{executable.parent}"', content)
                self.assertNotIn("_MEI", content)

    def test_macos_source_mode_writes_launch_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch()
            config = root / "config.json"

            with (
                patch("ip_guard.autostart.platform.system", return_value="Darwin"),
                patch("ip_guard.autostart.Path.home", return_value=root),
                patch.object(sys, "executable", str(python)),
            ):
                destination = install_autostart(config)
                with destination.open("rb") as stream:
                    payload = plistlib.load(stream)
                self.assertEqual("com.local.kiro-ip-guard", payload["Label"])
                self.assertEqual(str(python), payload["ProgramArguments"][0])
                self.assertIn("-m", payload["ProgramArguments"])
                self.assertTrue(payload["RunAtLoad"])


if __name__ == "__main__":
    unittest.main()
