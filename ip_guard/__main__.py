from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .autostart import install_autostart, remove_autostart
from .core import GuardService, default_config_dir
from .i18n import translate
from .logs import DailyLogHandler
from .resources import set_windows_app_id


def build_parser() -> argparse.ArgumentParser:
    text = lambda value: translate("auto", value)
    parser = argparse.ArgumentParser(description=text("按代理状态与公网 IP 地区策略守护 Kiro 进程"))
    parser.add_argument("--config", type=Path, help=text("自定义配置文件路径"))
    parser.add_argument("--once", action="store_true", help=text("检查一次、执行策略并退出"))
    parser.add_argument("--check-only", action="store_true", help=text("检查一次但不终止进程"))
    parser.add_argument("--settings", action="store_true", help=text("打开图形化设置窗口"))
    parser.add_argument("--install-autostart", action="store_true", help=text("安装当前程序的用户级开机自启"))
    parser.add_argument("--remove-autostart", action="store_true", help=text("删除用户级开机自启"))
    return parser


def configure_logging(config_dir: Path) -> None:
    # Daily files, kept for 7 days and capped at 30 MB in total; legacy
    # kiro-ip-guard.log* files from older versions are removed automatically.
    handler = DailyLogHandler(config_dir)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger("kiro_ip_guard")
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def main() -> int:
    set_windows_app_id()
    args = build_parser().parse_args()
    config_path = args.config or (default_config_dir() / "config.json")
    configure_logging(config_path.parent)

    if args.install_autostart:
        destination = install_autostart(config_path)
        print(f"已安装开机自启: {destination}")
        return 0
    if args.remove_autostart:
        destination = remove_autostart()
        print(f"已删除开机自启: {destination}")
        return 0
    if args.settings:
        try:
            from .settings import run_settings
        except ImportError as exc:
            raise SystemExit(f"图形界面不可用，请确认 Python 包含 Tkinter：{exc}") from exc
        return run_settings(config_path)

    service = GuardService(config_path)
    if args.once or args.check_only:
        result = service.check_once(enforce=not args.check_only)
        print(result.message)
        return 0 if result.compliant is True else (2 if result.compliant is False else 3)

    try:
        from .tray import TrayApplication
    except ImportError as exc:
        raise SystemExit(f"托盘依赖缺失，请先执行 pip install -r requirements.txt：{exc}") from exc
    TrayApplication(service).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
