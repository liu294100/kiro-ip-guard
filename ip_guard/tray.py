from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import pystray
from PIL import Image, ImageDraw
from pystray import Menu, MenuItem

from . import __version__
from .core import CheckResult, GuardService
from .i18n import translate
from .resources import icon_path
from .update import ReleaseInfo, check_latest_release

LOG = logging.getLogger("kiro_ip_guard")
_UPDATE_INTERVAL_SECONDS = 2 * 60 * 60


class TrayApplication:
    def __init__(self, service: GuardService) -> None:
        self.service = service
        self.service.on_result = self._on_result
        self._settings_lock = threading.Lock()
        self._update_lock = threading.Lock()
        self._update_stop_event = threading.Event()
        self._latest_release: ReleaseInfo | None = None
        self.icon = pystray.Icon(
            "kiro-ip-guard",
            self._make_icon("idle"),
            f"Kiro IP Guard v{__version__}",
            menu=self._build_menu(),
        )

    def _t(self, text: str, **values: object) -> str:
        return translate(self.service.config.language, text, **values)

    @staticmethod
    def _make_icon(state: str) -> Image.Image:
        colors = {"ok": "#16a34a", "blocked": "#dc2626", "idle": "#f59e0b"}
        asset = icon_path("small")
        if asset.is_file():
            with Image.open(asset) as source:
                image = source.convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)
            draw = ImageDraw.Draw(image)
            draw.ellipse((42, 42, 62, 62), fill=colors[state], outline="white", width=2)
            if state == "ok":
                draw.line((46, 52, 51, 57), fill="white", width=3)
                draw.line((51, 57, 59, 47), fill="white", width=3)
            elif state == "blocked":
                draw.line((47, 47, 58, 58), fill="white", width=3)
                draw.line((58, 47, 47, 58), fill="white", width=3)
            else:
                draw.line((52, 47, 52, 54), fill="white", width=3)
                draw.ellipse((51, 57, 53, 59), fill="white")
            return image

        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse((4, 4, 60, 60), fill="#111827", outline="#d1d5db", width=3)
        draw.polygon(((32, 12), (50, 21), (47, 43), (32, 54), (17, 43), (14, 21)), fill=colors[state])
        draw.rectangle((29, 23, 35, 40), fill="white")
        draw.ellipse((29, 44, 35, 50), fill="white")
        return image

    def _build_menu(self) -> Menu:
        return Menu(
            MenuItem(lambda _: self._status_text(), None, enabled=False),
            Menu.SEPARATOR,
            MenuItem(
                lambda _: self._t("开启监控"),
                self._toggle,
                checked=lambda _: self.service.config.enabled,
            ),
            MenuItem(lambda _: self._t("打开设置…"), self._open_settings, default=True),
            MenuItem(lambda _: self._t("立即检查（刷新地区缓存）"), self._check_now),
            MenuItem(lambda _: self._t("重新加载配置"), self._reload),
            MenuItem(lambda _: self._t("打开配置目录"), self._open_config_dir),
            Menu.SEPARATOR,
            MenuItem(lambda _: self._t("检查更新…"), self._check_updates),
            MenuItem(
                lambda _: self._t(
                    "下载新版本 v{version}…",
                    version=self._latest_release.version if self._latest_release else "",
                ),
                self._open_release,
                visible=lambda _: self._latest_release is not None,
            ),
            Menu.SEPARATOR,
            MenuItem(lambda _: self._t("退出"), self._exit),
        )

    def run(self) -> None:
        self.service.start()
        threading.Thread(
            target=self._automatic_update_loop,
            name="update-checker",
            daemon=True,
        ).start()
        self.icon.run()

    def _status_text(self) -> str:
        prefix = self._t("运行中") if self.service.config.enabled else self._t("已暂停")
        return f"{prefix} | {self.service.last_result.message[:80]}"

    def _toggle(self, icon: pystray.Icon, item: MenuItem) -> None:
        self.service.set_enabled(not self.service.config.enabled)
        icon.update_menu()

    def _check_now(self, icon: pystray.Icon, item: MenuItem) -> None:
        threading.Thread(
            target=self.service.check_once,
            kwargs={"enforce": True, "force_refresh": True},
            daemon=True,
        ).start()

    def _open_settings(self, icon: pystray.Icon, item: MenuItem) -> None:
        if not self._settings_lock.acquire(blocking=False):
            self._notify(self._t("设置窗口已经打开"), "Kiro IP Guard")
            return

        def worker() -> None:
            try:
                if getattr(sys, "frozen", False):
                    command = [sys.executable, "--settings", "--config", str(self.service.config_path)]
                    working_directory = None
                else:
                    command = [sys.executable, "-m", "ip_guard", "--settings", "--config", str(self.service.config_path)]
                    working_directory = str(Path(__file__).resolve().parents[1])
                completed = subprocess.run(command, cwd=working_directory, check=False)
                if completed.returncode == 0:
                    self.service.reload_config()
                    self._notify(self._t("设置窗口已关闭，配置已应用"), "Kiro IP Guard")
            except (OSError, ValueError) as exc:
                self._notify(self._t("无法打开或应用设置：{error}", error=exc), "Kiro IP Guard")
            finally:
                self._settings_lock.release()
                try:
                    self.icon.update_menu()
                except Exception:
                    LOG.debug("Tray menu update failed", exc_info=True)

        threading.Thread(target=worker, name="settings-launcher", daemon=True).start()

    def _reload(self, icon: pystray.Icon, item: MenuItem) -> None:
        try:
            self.service.reload_config()
            self._notify(self._t("配置已重新加载"), "Kiro IP Guard")
        except ValueError as exc:
            self._notify(str(exc), self._t("配置错误"))
        icon.update_menu()

    def _open_config_dir(self, icon: pystray.Icon, item: MenuItem) -> None:
        path = self.service.config_path.parent
        try:
            if sys.platform == "win32":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except OSError as exc:
            self._notify(self._t("无法打开目录: {error}", error=exc), "Kiro IP Guard")

    def _automatic_update_loop(self) -> None:
        while not self._update_stop_event.is_set():
            if self.service.config.check_updates:
                self._check_updates_worker(manual=False)
                wait_seconds = _UPDATE_INTERVAL_SECONDS
            else:
                wait_seconds = 60 * 60
            self._update_stop_event.wait(wait_seconds)

    def _check_updates(self, icon: pystray.Icon, item: MenuItem) -> None:
        threading.Thread(
            target=self._check_updates_worker,
            kwargs={"manual": True},
            name="manual-update-check",
            daemon=True,
        ).start()

    def _check_updates_worker(self, manual: bool) -> None:
        if not self._update_lock.acquire(blocking=False):
            return
        try:
            release = check_latest_release(__version__)
            self._latest_release = release
            if release is not None:
                self._notify(
                    self._t(
                        "发现新版本 v{version}，可从托盘菜单打开下载页。",
                        version=release.version,
                    ),
                    self._t("发现新版本"),
                )
            elif manual:
                self._notify(
                    self._t("当前已是最新版本 v{version}", version=__version__),
                    "Kiro IP Guard",
                )
        except Exception as exc:
            if manual:
                self._notify(self._t("无法检查更新：{error}", error=exc), "Kiro IP Guard")
            else:
                LOG.info("Automatic update check failed: %s", exc)
        finally:
            self._update_lock.release()
            try:
                self.icon.update_menu()
            except Exception:
                LOG.debug("Tray menu update failed", exc_info=True)

    def _open_release(self, icon: pystray.Icon, item: MenuItem) -> None:
        if self._latest_release is not None:
            webbrowser.open(self._latest_release.html_url)

    def _on_result(self, result: CheckResult) -> None:
        state = "idle" if result.compliant is None else ("ok" if result.compliant else "blocked")
        self.icon.icon = self._make_icon(state)
        self.icon.title = f"Kiro IP Guard - {result.message[:100]}"
        try:
            self.icon.update_menu()
        except Exception:
            LOG.debug("Tray menu is not ready", exc_info=True)
        if result.compliant is False or result.compliant is None:
            self._notify(result.message, "Kiro IP Guard")

    def _notify(self, message: str, title: str) -> None:
        try:
            self.icon.notify(message[:250], title)
        except Exception:
            LOG.debug("System notifications are unavailable", exc_info=True)

    def _exit(self, icon: pystray.Icon, item: MenuItem) -> None:
        self._update_stop_event.set()
        self.service.stop()
        icon.stop()
