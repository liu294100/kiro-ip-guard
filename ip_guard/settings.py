from __future__ import annotations

import ipaddress
import re
import threading
import tkinter as tk
import webbrowser
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Mapping
from urllib.parse import urlparse

from . import __version__
from .autostart import install_autostart, is_autostart_installed, remove_autostart
from .core import (
    ClashDetector,
    GeoLookup,
    GuardConfig,
    NETWORK_MODES,
    POLICY_MODES,
    evaluate_policy,
    get_system_proxies,
    load_config,
    resolve_ip_query_network_mode,
    save_config,
)
from .resources import apply_tk_window_icon
from .i18n import SUPPORTED_LANGUAGES, translate
from .update import ReleaseInfo, can_self_update, check_latest_release

COUNTRY_CODE_PATTERN = re.compile(r"^[A-Za-z]{2}$")


class ScrollableFrame(ttk.Frame):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.content = ttk.Frame(self.canvas, padding=(0, 0, 8, 0))
        self.window_id = self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.content.bind("<Configure>", self._update_scroll_region)
        self.canvas.bind("<Configure>", self._resize_content)
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)

    def _update_scroll_region(self, event: tk.Event[tk.Misc]) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _resize_content(self, event: tk.Event[tk.Misc]) -> None:
        self.canvas.itemconfigure(self.window_id, width=event.width)

    def _bind_mousewheel(self, event: tk.Event[tk.Misc]) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

    def _unbind_mousewheel(self, event: tk.Event[tk.Misc]) -> None:
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event: tk.Event[tk.Misc]) -> str:
        if getattr(event, "num", None) == 4:
            units = -3
        elif getattr(event, "num", None) == 5:
            units = 3
        else:
            units = -max(-3, min(3, int(getattr(event, "delta", 0) / 120)))
        self.canvas.yview_scroll(units, "units")
        return "break"


def _split_values(value: object) -> list[str]:
    text = str(value or "").replace("，", ",").replace(";", ",")
    return [item.strip() for line in text.splitlines() for item in line.split(",") if item.strip()]


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def config_from_form(values: Mapping[str, object]) -> GuardConfig:
    language = str(values.get("language", "auto") or "auto").strip()
    if language == "zh_CN":
        language = "zh-CN"
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError("language must be auto, zh-CN, or en")

    def text(message: str, **params: object) -> str:
        return translate(language, message, **params)

    policy_mode = str(values.get("policy_mode", "")).strip().lower()
    if policy_mode not in POLICY_MODES:
        raise ValueError(text("策略模式必须选择仅白名单、仅黑名单或组合模式"))
    network_mode = str(values.get("ip_query_network_mode", "")).strip().lower()
    if network_mode not in NETWORK_MODES:
        raise ValueError(text("网络检测模式必须选择自动、本机直连或系统代理出口"))

    try:
        interval = int(str(values.get("check_interval_seconds", "")).strip())
        cache_ttl = int(str(values.get("cache_ttl_seconds", "")).strip())
        timeout = int(str(values.get("request_timeout_seconds", "")).strip())
    except ValueError as exc:
        raise ValueError(text("检查间隔、IP 地区缓存时间和请求超时必须是整数")) from exc

    if not 1 <= interval <= 86400:
        raise ValueError(text("检查间隔必须在 1～86400 秒之间"))
    if not 0 <= cache_ttl <= 86400:
        raise ValueError(text("同一 IP 的地区缓存时间必须在 0～86400 秒之间；0 表示禁用缓存"))
    if not 1 <= timeout <= 60:
        raise ValueError(text("请求超时必须在 1～60 秒之间"))

    allowed = _split_values(values.get("allowed_country_codes"))
    blocked = _split_values(values.get("blocked_country_codes"))
    for code in allowed + blocked:
        if not COUNTRY_CODE_PATTERN.fullmatch(code):
            raise ValueError(text("国家/地区代码必须是两个英文字母: {code}", code=code))

    allowed_set = {code.upper() for code in allowed}
    blocked_set = {code.upper() for code in blocked}
    overlap = sorted(allowed_set & blocked_set)
    if policy_mode == "combined" and overlap:
        raise ValueError(
            text("组合模式下，以下地区同时存在于白名单和黑名单: {codes}", codes=", ".join(overlap))
        )
    if policy_mode == "allowlist" and not allowed_set:
        raise ValueError(text("仅白名单模式至少需要填写一个允许国家/地区"))

    networks = _split_values(values.get("blocked_ip_networks"))
    for network in networks:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise ValueError(text("无效的 IP/CIDR 黑名单项: {network}", network=network)) from exc

    process_names = _split_values(values.get("process_names"))
    if not process_names:
        raise ValueError(text("至少需要填写一个待保护的进程名"))

    clash_process_names = _split_values(values.get("clash_process_names"))
    if not clash_process_names:
        raise ValueError(text("至少需要填写一个代理工具进程名"))
    raw_clash_ports = _split_values(values.get("clash_proxy_ports"))
    try:
        clash_proxy_ports = [int(port) for port in raw_clash_ports]
    except ValueError as exc:
        raise ValueError(text("代理工具监听端口必须是整数")) from exc
    if not clash_proxy_ports or any(port < 1 or port > 65535 for port in clash_proxy_ports):
        raise ValueError(text("代理工具监听端口必须位于 1～65535，且至少填写一个"))

    providers = _split_values(values.get("providers"))
    geo_providers = _split_values(values.get("geo_providers"))
    if not providers:
        raise ValueError(text("至少需要填写一个公网 IP 查询源"))
    for url in providers + geo_providers:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(text("查询源必须是有效的 HTTPS URL: {url}", url=url))
    for url in geo_providers:
        if "{ip}" not in url:
            raise ValueError(text("GeoIP 查询源必须包含 {ip} 占位符: {url}", ip="{ip}", url=url))

    return GuardConfig(
        enabled=_as_bool(values.get("enabled")),
        policy_mode=policy_mode,
        ip_query_network_mode=network_mode,
        language=language,
        check_updates=_as_bool(values.get("check_updates", True)),
        auto_install_updates=_as_bool(values.get("auto_install_updates", True)),
        check_interval_seconds=interval,
        cache_ttl_seconds=cache_ttl,
        request_timeout_seconds=timeout,
        allowed_country_codes=allowed,
        blocked_country_codes=blocked,
        blocked_ip_networks=networks,
        process_names=process_names,
        fail_closed=_as_bool(values.get("fail_closed")),
        clash_required=_as_bool(values.get("clash_required")),
        clash_process_names=clash_process_names,
        clash_proxy_ports=clash_proxy_ports,
        claude_route_checks_enabled=_as_bool(values.get("claude_route_checks_enabled")),
        providers=providers,
        geo_providers=geo_providers,
    ).normalized()


class SettingsWindow:
    def __init__(self, root: tk.Tk, config_path: Path, config: GuardConfig) -> None:
        self.root = root
        self.config_path = config_path
        self.language = config.language
        self.testing = False
        self.checking_updates = False
        self.vars: dict[str, tk.Variable] = {
            "enabled": tk.BooleanVar(),
            "policy_mode": tk.StringVar(),
            "ip_query_network_mode": tk.StringVar(),
            "language": tk.StringVar(),
            "check_updates": tk.BooleanVar(),
            "auto_install_updates": tk.BooleanVar(),
            "check_interval_seconds": tk.StringVar(),
            "cache_ttl_seconds": tk.StringVar(),
            "request_timeout_seconds": tk.StringVar(),
            "allowed_country_codes": tk.StringVar(),
            "blocked_country_codes": tk.StringVar(),
            "fail_closed": tk.BooleanVar(),
            "clash_required": tk.BooleanVar(),
            "claude_route_checks_enabled": tk.BooleanVar(),
        }
        self.text_fields: dict[str, tk.Text] = {}
        self.status = tk.StringVar(value=self._t("配置文件：{path}", path=config_path))
        self.autostart_status = tk.StringVar()
        self.last_checked = tk.StringVar(value=self._t("尚未检测"))
        self.proxy_status = tk.StringVar(value=self._t("系统代理：尚未读取"))
        self.update_status = tk.StringVar(value=self._t("尚未检查更新"))

        root.title(f"Kiro IP Guard v{__version__} {self._t('设置')}")
        apply_tk_window_icon(root)
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        width = min(940, max(680, screen_width - 80))
        height = min(900, max(600, screen_height - 60))
        x = max(0, (screen_width - width) // 2)
        y = max(0, (screen_height - height) // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")
        root.minsize(min(680, width), min(600, height))
        self._set_native_appearance()
        self._build_ui()
        self._load_into_form(config)
        self._refresh_autostart_status()
        root.protocol("WM_DELETE_WINDOW", root.destroy)

    def _t(self, text: str, **values: object) -> str:
        return translate(self.language, text, **values)

    def _refresh_autostart_status(self) -> None:
        try:
            installed = is_autostart_installed()
            self.autostart_status.set(
                self._t("当前：已开启开机启动")
                if installed
                else self._t("当前：手动运行（未开机启动）")
            )
        except RuntimeError as exc:
            self.autostart_status.set(str(exc))

    def _install_autostart(self) -> None:
        try:
            destination = install_autostart(self.config_path)
            self.status.set(self._t("已开启用户级开机启动：{destination}", destination=destination))
            self._refresh_autostart_status()
        except (OSError, RuntimeError) as exc:
            messagebox.showerror(self._t("无法开启开机启动"), str(exc), parent=self.root)

    def _remove_autostart(self) -> None:
        try:
            destination = remove_autostart()
            self.status.set(self._t("已关闭用户级开机启动：{destination}", destination=destination))
            self._refresh_autostart_status()
        except (OSError, RuntimeError) as exc:
            messagebox.showerror(self._t("无法关闭开机启动"), str(exc), parent=self.root)

    def _set_native_appearance(self) -> None:
        style = ttk.Style(self.root)
        available = style.theme_names()
        for preferred in ("vista", "aqua", "clam"):
            if preferred in available:
                style.theme_use(preferred)
                break

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=1)

        ttk.Label(
            outer,
            text=f"Kiro IP Guard v{__version__}",
            font=("TkDefaultFont", 16, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            outer,
            text=self._t("修改地区策略和后台监控参数。保存后，正在运行的托盘程序会自动应用。"),
        ).grid(row=1, column=0, sticky="w", pady=(2, 10))

        notebook = ttk.Notebook(outer)
        notebook.grid(row=2, column=0, sticky="nsew")
        basic_page = ttk.Frame(notebook, padding=(4, 8, 4, 4))
        startup = ttk.Frame(notebook, padding=14)
        advanced = ttk.Frame(notebook, padding=14)
        results = ttk.Frame(notebook, padding=14)
        notebook.add(basic_page, text=self._t("策略与监控"))
        notebook.add(startup, text=self._t("启动与更新"))
        notebook.add(advanced, text=self._t("查询源"))
        notebook.add(results, text=self._t("检测结果"))
        basic_scroller = ScrollableFrame(basic_page)
        basic_scroller.pack(fill="both", expand=True)
        self._build_basic_tab(basic_scroller.content)
        self._build_startup_tab(startup)
        self._build_advanced_tab(advanced)
        self._build_results_tab(results)

        ttk.Separator(outer).grid(row=3, column=0, sticky="ew", pady=(12, 8))
        ttk.Label(outer, textvariable=self.status, wraplength=820).grid(
            row=4, column=0, sticky="ew"
        )

        buttons = ttk.Frame(outer)
        buttons.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(buttons, text=self._t("恢复默认值"), command=self._reset_defaults).pack(side="left")
        ttk.Button(buttons, text=self._t("取消"), command=self.root.destroy).pack(side="right")
        ttk.Button(buttons, text=self._t("保存并关闭"), command=lambda: self._save(True)).pack(
            side="right", padx=8
        )
        ttk.Button(buttons, text=self._t("保存"), command=lambda: self._save(False)).pack(side="right")

    def _build_basic_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)
        row = 0
        ttk.Checkbutton(parent, text=self._t("开启后台监控"), variable=self.vars["enabled"]).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(0, 10)
        )
        row += 1
        ttk.Checkbutton(
            parent,
            text=self._t("要求系统代理或 TUN/VPN 已实际启用（与公网 IP 策略同时满足）"),
            variable=self.vars["clash_required"],
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, 10))
        row += 1
        mode_frame = ttk.LabelFrame(parent, text=self._t("策略模式"), padding=8)
        mode_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Radiobutton(
            mode_frame,
            text=self._t("仅白名单（只允许名单内地区）"),
            value="allowlist",
            variable=self.vars["policy_mode"],
        ).pack(anchor="w")
        ttk.Radiobutton(
            mode_frame,
            text=self._t("仅黑名单（只禁止名单内地区/IP）"),
            value="blocklist",
            variable=self.vars["policy_mode"],
        ).pack(anchor="w")
        ttk.Radiobutton(
            mode_frame,
            text=self._t("组合模式（先黑名单，再检查白名单）"),
            value="combined",
            variable=self.vars["policy_mode"],
        ).pack(anchor="w")
        row += 1
        self._entry(
            parent,
            row,
            self._t("检查间隔（秒）"),
            "check_interval_seconds",
            self._t("默认 1 秒；每次都会重新判断策略"),
        )
        row += 1
        self._entry(
            parent,
            row,
            self._t("同一 IP 地区缓存（秒）"),
            "cache_ttl_seconds",
            self._t("默认 600 秒；当前出口 IP 本身不会缓存"),
        )
        row += 1
        self._entry(parent, row, self._t("请求超时（秒）"), "request_timeout_seconds")
        row += 1
        self._entry(
            parent,
            row,
            self._t("允许国家/地区"),
            "allowed_country_codes",
            self._t("例如：US, CA；留空表示不启用白名单"),
        )
        row += 1
        self._entry(
            parent,
            row,
            self._t("禁止国家/地区"),
            "blocked_country_codes",
            self._t("默认：CN, CU, HK, IR, KP, MO, RU, SY"),
        )
        row += 1
        self._text(
            parent,
            row,
            self._t("IP/CIDR 黑名单"),
            "blocked_ip_networks",
            5,
            self._t("每行一个，例如：203.0.113.0/24"),
        )
        row += 1
        self._text(
            parent,
            row,
            self._t("Kiro 进程名"),
            "process_names",
            4,
            self._t("每行一个，按名称精确匹配"),
        )
        row += 1
        ttk.Checkbutton(
            parent,
            text=self._t("查询源全部失败时也终止 Kiro（故障关闭，可能因断网误杀）"),
            variable=self.vars["fail_closed"],
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(10, 0))

    def _build_startup_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(
            parent,
            text=self._t("监控开关与开机启动互相独立：可以手动运行并监控，也可以设置为登录系统后自动驻留。"),
            wraplength=780,
        ).pack(anchor="w", pady=(0, 12))

        language_frame = ttk.LabelFrame(parent, text=self._t("语言"), padding=12)
        language_frame.pack(fill="x", pady=(0, 12))
        ttk.Radiobutton(
            language_frame,
            text=self._t("系统默认"),
            value="auto",
            variable=self.vars["language"],
        ).pack(side="left")
        ttk.Radiobutton(
            language_frame,
            text="中文",
            value="zh-CN",
            variable=self.vars["language"],
        ).pack(side="left", padx=(14, 0))
        ttk.Radiobutton(
            language_frame,
            text="English",
            value="en",
            variable=self.vars["language"],
        ).pack(side="left", padx=(14, 0))
        ttk.Label(
            language_frame,
            text=self._t("保存后重新打开窗口和托盘菜单即可应用语言。"),
            foreground="#666666",
        ).pack(side="left", padx=(18, 0))

        status_frame = ttk.LabelFrame(parent, text=self._t("用户级开机启动"), padding=12)
        status_frame.pack(fill="x", pady=(0, 12))
        ttk.Label(status_frame, textvariable=self.autostart_status).pack(anchor="w", pady=(0, 12))
        actions = ttk.Frame(status_frame)
        actions.pack(fill="x")
        ttk.Button(actions, text=self._t("开启开机启动"), command=self._install_autostart).pack(side="left")
        ttk.Button(actions, text=self._t("关闭开机启动"), command=self._remove_autostart).pack(
            side="left", padx=8
        )
        ttk.Label(
            status_frame,
            text=self._t(
                "源码模式会记录当前虚拟环境；onefile 或 macOS App 模式会记录当前可执行文件。移动程序位置后，请重新开启一次开机启动。"
            ),
            wraplength=760,
            foreground="#666666",
        ).pack(anchor="w", pady=(12, 0))

        update_frame = ttk.LabelFrame(parent, text=self._t("软件更新"), padding=12)
        update_frame.pack(fill="x")
        ttk.Checkbutton(
            update_frame,
            text=self._t("启动后自动检查 GitHub Releases；持续运行时每 2 小时检查一次"),
            variable=self.vars["check_updates"],
        ).pack(anchor="w")
        ttk.Checkbutton(
            update_frame,
            text=self._t("发现新版本时自动下载、校验并安装，然后重启（仅打包版）"),
            variable=self.vars["auto_install_updates"],
        ).pack(anchor="w", pady=(6, 0))
        update_actions = ttk.Frame(update_frame)
        update_actions.pack(fill="x", pady=(10, 0))
        ttk.Button(
            update_actions,
            text=self._t("检查更新"),
            command=self._check_for_updates,
        ).pack(side="left")
        ttk.Label(
            update_actions,
            text=self._t("当前版本：v{version}", version=__version__),
        ).pack(side="left", padx=(12, 0))
        ttk.Label(update_frame, textvariable=self.update_status, foreground="#555555").pack(
            anchor="w", pady=(8, 0)
        )

    def _check_for_updates(self) -> None:
        if self.checking_updates:
            return
        self.checking_updates = True
        self.update_status.set(self._t("正在检查 GitHub Releases……"))

        def worker() -> None:
            release: ReleaseInfo | None = None
            error: Exception | None = None
            try:
                release = check_latest_release(__version__)
            except Exception as exc:
                error = exc
            try:
                self.root.after(0, lambda: self._finish_update_check(release, error))
            except (tk.TclError, RuntimeError):
                pass

        threading.Thread(target=worker, name="settings-update-check", daemon=True).start()

    def _finish_update_check(
        self,
        release: ReleaseInfo | None,
        error: Exception | None,
    ) -> None:
        self.checking_updates = False
        if error is not None:
            self.update_status.set(self._t("检查更新失败：{error}", error=error))
            return
        if release is None:
            self.update_status.set(self._t("当前已是最新版本 v{version}。", version=__version__))
            return
        self.update_status.set(self._t("发现新版本 v{version}。", version=release.version))
        if can_self_update():
            # The tray process owns the running executable, so it performs the
            # replacement and restart; this window only points the user there.
            messagebox.showinfo(
                self._t("发现新版本"),
                self._t(
                    "发现新版本 v{version}。请在托盘菜单点击“安装更新 v{version}”，程序会自动下载、替换并重启。",
                    version=release.version,
                ),
                parent=self.root,
            )
        elif messagebox.askyesno(
            self._t("发现新版本"),
            self._t("发现新版本 v{version}。是否打开 GitHub Release 下载页？", version=release.version),
            parent=self.root,
        ):
            webbrowser.open(release.html_url)

    def _build_advanced_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)
        network_frame = ttk.LabelFrame(parent, text=self._t("本机公网 IP 检测方式"), padding=8)
        network_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Radiobutton(
            network_frame,
            text=self._t("自动选择（推荐；系统代理启用时走代理，否则走直连/TUN 路由）"),
            value="auto",
            variable=self.vars["ip_query_network_mode"],
        ).pack(anchor="w")
        ttk.Radiobutton(
            network_frame,
            text=self._t("始终本机直连（绕过 HTTP_PROXY、HTTPS_PROXY 和系统 HTTP 代理）"),
            value="direct",
            variable=self.vars["ip_query_network_mode"],
        ).pack(anchor="w")
        ttk.Radiobutton(
            network_frame,
            text=self._t("系统代理出口（检测代理线路对外显示的 IP）"),
            value="system_proxy",
            variable=self.vars["ip_query_network_mode"],
        ).pack(anchor="w")
        ttk.Checkbutton(
            parent,
            text=self._t("检测 Claude / Anthropic 实际访问路径（推荐开启）"),
            variable=self.vars["claude_route_checks_enabled"],
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Label(
            parent,
            text=self._t("程序以实际启用且可连接的系统代理或活动 TUN/VPN 为准；仅运行工具或监听端口不算启用。"),
            wraplength=780,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 12))
        self._text(
            parent,
            3,
            self._t("代理工具进程名"),
            "clash_process_names",
            5,
            self._t("用于辅助显示；未知工具只要系统代理/TUN 已启用也可识别"),
        )
        self._text(
            parent,
            4,
            self._t("常用监听端口"),
            "clash_proxy_ports",
            3,
            self._t("仅用于诊断，不再作为代理已启用的依据"),
        )
        self._text(
            parent,
            5,
            self._t("公网 IP 查询源"),
            "providers",
            7,
            self._t("每行一个；Cloudflare trace 和 HTTPS JSON API 均支持"),
        )
        self._text(
            parent,
            6,
            self._t("GeoIP 补充源"),
            "geo_providers",
            5,
            self._t("每行一个，必须包含 {ip} 占位符", ip="{ip}"),
        )

    def _build_results_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(
            parent,
            text=self._t(
                "这里显示本机访问每个查询域名时，对方看到的本机公网出口 IP（不是网站服务器 IP）。切换线路后点击检测，或等待后台下一个检查周期。"
            ),
            wraplength=800,
        ).pack(anchor="w")
        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(10, 8))
        ttk.Button(
            actions,
            text=self._t("检测当前出口（不终止进程）"),
            command=self._test_ip,
        ).pack(side="left")
        ttk.Label(actions, textvariable=self.last_checked).pack(side="right")
        ttk.Label(parent, textvariable=self.proxy_status, foreground="#555555").pack(anchor="w", pady=(0, 8))

        columns = ("source", "ip", "country", "state")
        self.result_tree = ttk.Treeview(parent, columns=columns, show="headings", height=12)
        headings = {
            "source": self._t("查询路径"),
            "ip": self._t("本机公网出口 IP"),
            "country": self._t("国家/地区"),
            "state": self._t("策略结果"),
        }
        widths = {"source": 250, "ip": 180, "country": 100, "state": 100}
        for column in columns:
            self.result_tree.heading(column, text=headings[column])
            self.result_tree.column(column, width=widths[column], minwidth=80, stretch=column == "source")
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.result_tree.pack(fill="both", expand=True)

    def _entry(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        key: str,
        hint: str = "",
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="nw", padx=(0, 12), pady=6)
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=1, sticky="ew", pady=6)
        frame.columnconfigure(0, weight=1)
        ttk.Entry(frame, textvariable=self.vars[key]).grid(row=0, column=0, sticky="ew")
        if hint:
            ttk.Label(frame, text=hint, foreground="#666666").grid(row=1, column=0, sticky="w", pady=(2, 0))

    def _text(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        key: str,
        height: int,
        hint: str,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="nw", padx=(0, 12), pady=6)
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=1, sticky="nsew", pady=6)
        frame.columnconfigure(0, weight=1)
        text = tk.Text(frame, height=height, wrap="none", undo=True)
        text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=scrollbar.set)
        ttk.Label(frame, text=hint, foreground="#666666").grid(row=1, column=0, sticky="w", pady=(2, 0))
        self.text_fields[key] = text

    def _load_into_form(self, config: GuardConfig) -> None:
        values = asdict(config)
        for key, variable in self.vars.items():
            value = values[key]
            if isinstance(variable, tk.BooleanVar):
                variable.set(bool(value))
            elif isinstance(value, list):
                variable.set(", ".join(value))
            else:
                variable.set(str(value))
        for key, text in self.text_fields.items():
            text.delete("1.0", "end")
            text.insert("1.0", "\n".join(str(value) for value in values[key]))

    def _form_values(self) -> dict[str, object]:
        values = {key: variable.get() for key, variable in self.vars.items()}
        values.update({key: text.get("1.0", "end").strip() for key, text in self.text_fields.items()})
        return values

    def _read_config(self) -> GuardConfig:
        return config_from_form(self._form_values())

    def _save(self, close: bool) -> None:
        try:
            config = self._read_config()
            save_config(self.config_path, config)
        except (OSError, ValueError) as exc:
            messagebox.showerror(self._t("无法保存配置"), str(exc), parent=self.root)
            self.status.set(self._t("保存失败：{error}", error=exc))
            return
        self.status.set(self._t("配置已保存，后台守卫将自动重新加载。"))
        if close:
            self.root.destroy()

    def _reset_defaults(self) -> None:
        if messagebox.askyesno(
            self._t("恢复默认值"),
            self._t("确定把窗口中的内容恢复为默认值吗？尚未点击保存。"),
            parent=self.root,
        ):
            self._load_into_form(GuardConfig().normalized())
            self.status.set(self._t("已恢复默认值；点击保存后才会生效。"))

    def _test_ip(self) -> None:
        if self.testing:
            return
        try:
            config = self._read_config()
        except ValueError as exc:
            messagebox.showerror(self._t("配置有误"), str(exc), parent=self.root)
            return
        self.testing = True
        self.status.set(self._t("正在查询各路径看到的本机公网出口 IP……本次测试不会终止进程。"))
        self.last_checked.set(self._t("检测中……"))

        def worker() -> None:
            rows: list[tuple[str, str, str, str]] = []
            clash_status = ClashDetector().detect(config)
            configured_network_mode = config.ip_query_network_mode
            effective_network_mode = resolve_ip_query_network_mode(config, clash_status)
            config.ip_query_network_mode = effective_network_mode
            if effective_network_mode == "direct":
                network_summary = self._t("本机直连（绕过 HTTP(S) 系统代理；TUN 路由仍会生效）")
            else:
                proxies = get_system_proxies()
                proxy_types = sorted(key for key in proxies if key.lower() in {"http", "https", "all", "socks"})
                network_summary = self._t(
                    "系统代理出口；代理类型：{types}",
                    types=", ".join(proxy_types) if proxy_types else self._t("未发现代理配置"),
                )
            if configured_network_mode == "auto":
                network_summary = self._t("自动选择 → {summary}", summary=network_summary)
            requirement = self._t("必需") if config.clash_required else self._t("仅显示，不参与拦截")
            proxy_summary = self._t(
                "代理状态（{requirement}）：{reason}；IP 检测：{summary}",
                requirement=requirement,
                reason=clash_status.reason,
                summary=network_summary,
            )
            try:
                infos = GeoLookup().lookup_all(config, force_refresh=True)
                for info in infos:
                    policy = evaluate_policy(info, config)
                    if not policy.compliant or (config.clash_required and clash_status.active is False):
                        state = self._t("不合规")
                    elif config.clash_required and clash_status.active is None:
                        state = self._t("无法确认")
                    else:
                        state = self._t("合规")
                    source = " + ".join(
                        urlparse(part.strip()).netloc or part.strip()
                        for part in info.provider.split(" + ")
                    )
                    rows.append((source, info.ip, info.country_code, state))
                blocked_state = self._t("不合规")
                unknown_state = self._t("无法确认")
                failed = sum(1 for row in rows if row[3] == blocked_state)
                unknown = sum(1 for row in rows if row[3] == unknown_state)
                message = self._t(
                    "检测完成：{count} 个路径，{failed} 个不合规，{unknown} 个无法确认。",
                    count=len(rows),
                    failed=failed,
                    unknown=unknown,
                )
            except Exception as exc:
                message = self._t("测试失败：{error}", error=exc)
            try:
                self.root.after(0, lambda: self._finish_test(message, rows, proxy_summary))
            except (tk.TclError, RuntimeError):
                pass

        threading.Thread(target=worker, name="settings-ip-test", daemon=True).start()

    def _finish_test(
        self,
        message: str,
        rows: list[tuple[str, str, str, str]],
        proxy_summary: str,
    ) -> None:
        self.testing = False
        self.status.set(message)
        self.proxy_status.set(proxy_summary)
        self.last_checked.set(
            self._t("最近检测：{time}", time=datetime.now().strftime("%H:%M:%S"))
        )
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        for row in rows:
            self.result_tree.insert("", "end", values=row, tags=(row[3],))
        self.result_tree.tag_configure(self._t("合规"), foreground="#15803d")
        self.result_tree.tag_configure(self._t("不合规"), foreground="#b91c1c")
        self.result_tree.tag_configure(self._t("无法确认"), foreground="#b45309")


def run_settings(config_path: Path) -> int:
    root = tk.Tk()
    try:
        config = load_config(config_path)
    except ValueError as exc:
        root.withdraw()
        messagebox.showerror(translate("auto", "配置文件错误"), str(exc), parent=root)
        root.destroy()
        return 2
    SettingsWindow(root, config_path, config)
    root.mainloop()
    return 0
