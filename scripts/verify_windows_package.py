from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ip_guard import __version__

EXE = ROOT / "dist" / "KiroIPGuard" / "KiroIPGuard.exe"
WM_GETICON = 0x007F
ICON_SMALL = 0
ICON_BIG = 1
GCLP_HICON = -14
GCLP_HICONSM = -34


def windows_for_pid(pid: int) -> list[int]:
    user32 = ctypes.windll.user32
    handles: list[int] = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @callback_type
    def callback(hwnd: int, _: int) -> bool:
        window_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        if window_pid.value == pid and user32.IsWindowVisible(hwnd):
            handles.append(hwnd)
        return True

    user32.EnumWindows(callback, 0)
    return handles


def window_title(hwnd: int) -> str:
    user32 = ctypes.windll.user32
    length = user32.GetWindowTextLengthW(hwnd)
    buffer = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buffer, len(buffer))
    return buffer.value


def icon_handles(hwnd: int) -> list[int]:
    user32 = ctypes.windll.user32
    user32.SendMessageW.restype = ctypes.c_void_p
    user32.GetClassLongPtrW.restype = ctypes.c_void_p
    return [
        user32.SendMessageW(hwnd, WM_GETICON, ICON_BIG, 0) or 0,
        user32.SendMessageW(hwnd, WM_GETICON, ICON_SMALL, 0) or 0,
        user32.GetClassLongPtrW(hwnd, GCLP_HICON) or 0,
        user32.GetClassLongPtrW(hwnd, GCLP_HICONSM) or 0,
    ]


def main() -> int:
    if not EXE.is_file():
        raise FileNotFoundError(EXE)
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "config.json"
        process = subprocess.Popen([str(EXE), "--settings", "--config", str(config)])
        try:
            deadline = time.monotonic() + 30
            handles: list[int] = []
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    pids = [process.pid] + [
                        child.pid for child in psutil.Process(process.pid).children(recursive=True)
                    ]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pids = [process.pid]
                handles = [handle for pid in pids for handle in windows_for_pid(pid)]
                if handles:
                    break
                time.sleep(0.2)
            if process.poll() is not None:
                raise RuntimeError(f"设置窗口提前退出，退出码 {process.returncode}")
            if not handles:
                raise RuntimeError("未找到打包程序的可见设置窗口")
            icons = [value for hwnd in handles for value in icon_handles(hwnd)]
            titles = [window_title(hwnd) for hwnd in handles]
            if not any(f"v{__version__}" in title for title in titles):
                raise RuntimeError(f"设置窗口版本标题不匹配: {titles}")
            if not any(icons):
                raise RuntimeError("设置窗口和窗口类均未设置图标句柄")
            payload = json.loads(config.read_text(encoding="utf-8"))
            if payload.get("config_version") != 2:
                raise RuntimeError(f"默认配置版本错误: {payload.get('config_version')}")
            if payload.get("ip_query_network_mode") != "auto":
                raise RuntimeError(
                    "默认网络模式错误: " + str(payload.get("ip_query_network_mode"))
                )
            proxy_processes = set(payload.get("clash_process_names") or [])
            if not {"mihomo.exe", "v2rayn.exe", "sing-box.exe", "wireguard.exe"}.issubset(
                proxy_processes
            ):
                raise RuntimeError("默认多代理工具进程名未打包完整")
            proxy_ports = set(payload.get("clash_proxy_ports") or [])
            if not {1080, 7890, 10808}.issubset(proxy_ports):
                raise RuntimeError("默认多代理工具端口未打包完整")
            print(
                f"PACKAGED_WINDOW_ICON_OK pid={process.pid} "
                f"windows={len(handles)} title={titles[0]}",
                flush=True,
            )
            return 0
        finally:
            try:
                root_process = psutil.Process(process.pid)
                targets = root_process.children(recursive=True) + [root_process]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                targets = []
            for target in targets:
                try:
                    target.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            _, alive = psutil.wait_procs(targets, timeout=5)
            for target in alive:
                try:
                    target.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if process.poll() is None:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
