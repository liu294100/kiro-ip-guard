from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ip_guard.core import GuardConfig, GuardService, save_config
from ip_guard.settings import config_from_form


def valid_form() -> dict[str, object]:
    return {
        "enabled": True,
        "policy_mode": "combined",
        "ip_query_network_mode": "direct",
        "language": "zh-CN",
        "check_updates": True,
        "check_interval_seconds": "10",
        "cache_ttl_seconds": "600",
        "request_timeout_seconds": "5",
        "allowed_country_codes": "US, CA",
        "blocked_country_codes": "CN\nHK",
        "blocked_ip_networks": "203.0.113.0/24\n2001:db8::/32",
        "process_names": "kiro.exe\nkiro-cli.exe",
        "fail_closed": False,
        "clash_required": True,
        "clash_process_names": "clash.exe\nmihomo.exe",
        "clash_proxy_ports": "7890\n7897",
        "claude_route_checks_enabled": True,
        "providers": "https://ipwho.is/\nhttps://ipapi.co/json/",
        "geo_providers": "https://ip.net.coffee/api/geoip/{ip}",
    }


class SettingsValidationTests(unittest.TestCase):
    def test_valid_form_is_normalized(self) -> None:
        config = config_from_form(valid_form())
        self.assertEqual(10, config.check_interval_seconds)
        self.assertEqual(600, config.cache_ttl_seconds)
        self.assertTrue(config.claude_route_checks_enabled)
        self.assertIn("https://claude.ai/cdn-cgi/trace", config.providers)
        self.assertEqual("combined", config.policy_mode)
        self.assertEqual("direct", config.ip_query_network_mode)
        self.assertEqual(["CA", "US"], config.allowed_country_codes)
        self.assertEqual(["CN", "HK"], config.blocked_country_codes)
        self.assertEqual(["kiro.exe", "kiro-cli.exe"], config.process_names)
        self.assertTrue(config.clash_required)
        self.assertEqual(["clash.exe", "mihomo.exe"], config.clash_process_names)
        self.assertEqual([7890, 7897], config.clash_proxy_ports)

    def test_disabling_claude_routes_removes_trace_providers(self) -> None:
        values = valid_form()
        values["claude_route_checks_enabled"] = False
        values["providers"] = "https://ipwho.is/\nhttps://claude.ai/cdn-cgi/trace"
        config = config_from_form(values)
        self.assertFalse(config.claude_route_checks_enabled)
        self.assertNotIn("https://claude.ai/cdn-cgi/trace", config.providers)

    def test_auto_network_mode_is_accepted(self) -> None:
        values = valid_form()
        values["ip_query_network_mode"] = "auto"
        self.assertEqual("auto", config_from_form(values).ip_query_network_mode)

    def test_rejects_invalid_network_mode(self) -> None:
        values = valid_form()
        values["ip_query_network_mode"] = "unknown"
        with self.assertRaisesRegex(ValueError, "网络检测模式"):
            config_from_form(values)

    def test_rejects_invalid_clash_proxy_port(self) -> None:
        values = valid_form()
        values["clash_proxy_ports"] = "7890\n70000"
        with self.assertRaisesRegex(ValueError, "代理工具监听端口"):
            config_from_form(values)

    def test_rejects_missing_clash_process_names(self) -> None:
        values = valid_form()
        values["clash_process_names"] = ""
        with self.assertRaisesRegex(ValueError, "代理工具进程名"):
            config_from_form(values)

    def test_allowlist_mode_requires_entries(self) -> None:
        values = valid_form()
        values["policy_mode"] = "allowlist"
        values["allowed_country_codes"] = ""
        with self.assertRaisesRegex(ValueError, "至少需要"):
            config_from_form(values)

    def test_non_combined_mode_can_keep_overlapping_lists(self) -> None:
        values = valid_form()
        values["policy_mode"] = "allowlist"
        values["allowed_country_codes"] = "US"
        values["blocked_country_codes"] = "US"
        self.assertEqual("allowlist", config_from_form(values).policy_mode)

    def test_rejects_invalid_cache_ttl(self) -> None:
        values = valid_form()
        values["cache_ttl_seconds"] = "-1"
        with self.assertRaisesRegex(ValueError, "缓存时间"):
            config_from_form(values)

    def test_rejects_invalid_country_code(self) -> None:
        values = valid_form()
        values["allowed_country_codes"] = "USA"
        with self.assertRaisesRegex(ValueError, "两个英文字母"):
            config_from_form(values)

    def test_rejects_allow_block_overlap(self) -> None:
        values = valid_form()
        values["blocked_country_codes"] = "US"
        with self.assertRaisesRegex(ValueError, "同时存在"):
            config_from_form(values)

    def test_rejects_invalid_cidr(self) -> None:
        values = valid_form()
        values["blocked_ip_networks"] = "999.1.1.1/24"
        with self.assertRaisesRegex(ValueError, "无效的 IP/CIDR"):
            config_from_form(values)

    def test_rejects_geo_provider_without_placeholder(self) -> None:
        values = valid_form()
        values["geo_providers"] = "https://example.com/geoip"
        with self.assertRaisesRegex(ValueError, "占位符"):
            config_from_form(values)


class ConfigReloadTests(unittest.TestCase):
    def test_service_reloads_external_config_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            save_config(path, GuardConfig(enabled=True, check_interval_seconds=60))
            service = GuardService(path)
            previous_mtime = path.stat().st_mtime_ns

            save_config(path, GuardConfig(enabled=False, check_interval_seconds=120))
            stat = path.stat()
            os.utime(path, ns=(stat.st_atime_ns, previous_mtime + 1_000_000_000))

            self.assertTrue(service.reload_if_changed())
            self.assertFalse(service.config.enabled)
            self.assertEqual(120, service.config.check_interval_seconds)
            self.assertFalse(service.reload_if_changed())


if __name__ == "__main__":
    unittest.main()
