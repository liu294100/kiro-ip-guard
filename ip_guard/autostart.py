from __future__ import annotations

import os
import platform
import plistlib
import subprocess
import sys
from pathlib import Path

AUTOSTART_NAME = "KiroIPGuard"
LAUNCH_AGENT_ID = "com.local.kiro-ip-guard"


def _launch_command(config_path: Path) -> list[str]:
    executable = Path(sys.executable).resolve()
    if platform.system() == "Windows" and not getattr(sys, "frozen", False):
        pythonw = executable.with_name("pythonw.exe")
        if pythonw.exists():
            executable = pythonw
    if getattr(sys, "frozen", False):
        return [str(executable), "--config", str(config_path)]
    return [str(executable), "-m", "ip_guard", "--config", str(config_path)]


def _working_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def autostart_path(system: str | None = None) -> Path:
    system = system or platform.system()
    if system == "Windows":
        appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / f"{AUTOSTART_NAME}.cmd"
    if system == "Darwin":
        return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_ID}.plist"
    raise RuntimeError("开机自启仅支持 Windows 和 macOS")


def is_autostart_installed() -> bool:
    return autostart_path().is_file()


def install_autostart(config_path: Path) -> Path:
    system = platform.system()
    command = _launch_command(config_path)
    working_dir = _working_directory()

    if system == "Windows":
        destination = autostart_path(system)
        destination.parent.mkdir(parents=True, exist_ok=True)
        quoted = subprocess.list2cmdline(command)
        destination.write_text(
            f'@echo off\r\ncd /d "{working_dir}"\r\nstart "" {quoted}\r\n',
            encoding="utf-8",
        )
        return destination

    if system == "Darwin":
        destination = autostart_path(system)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "Label": LAUNCH_AGENT_ID,
            "ProgramArguments": command,
            "WorkingDirectory": str(working_dir),
            "RunAtLoad": True,
            "KeepAlive": False,
        }
        with destination.open("wb") as stream:
            plistlib.dump(payload, stream)
        return destination

    raise RuntimeError("开机自启安装仅支持 Windows 和 macOS")


def remove_autostart() -> Path:
    destination = autostart_path()
    destination.unlink(missing_ok=True)
    return destination
