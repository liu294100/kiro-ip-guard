from __future__ import annotations

import ctypes
import logging
import platform
import sys
from pathlib import Path
from typing import Any

LOG = logging.getLogger("kiro_ip_guard")
APP_USER_MODEL_ID = "Kiro.IPGuard"


def resource_path(relative_path: str) -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    else:
        base = Path(__file__).resolve().parents[1]
    return base / relative_path


def icon_path(kind: str = "png") -> Path:
    names = {
        "png": "assets/kiro-ip-guard.png",
        "small": "assets/kiro-ip-guard-64.png",
        "ico": "assets/kiro-ip-guard.ico",
        "icns": "assets/kiro-ip-guard.icns",
    }
    return resource_path(names[kind])


def set_windows_app_id() -> None:
    if platform.system() != "Windows":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except (AttributeError, OSError):
        LOG.debug("无法设置 Windows AppUserModelID", exc_info=True)


def apply_tk_window_icon(root: Any) -> None:
    try:
        import tkinter as tk

        png = icon_path("png")
        if png.is_file():
            image = tk.PhotoImage(file=str(png))
            root.iconphoto(True, image)
            root._kiro_icon_image = image
        if platform.system() == "Windows":
            ico = icon_path("ico")
            if ico.is_file():
                root.iconbitmap(str(ico))
    except Exception:
        LOG.debug("无法设置窗口图标", exc_info=True)
