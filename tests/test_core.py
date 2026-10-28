from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from ip_guard.core import (
    ClashDetector,
    ClashStatus,
    GeoLookup,
    GuardConfig,
    GuardService,
    IpInfo,
    ProcessTerminator,
    evaluate_policy,
    get_system_proxies,
    load_config,
    resolve_ip_query_network_mode,
    save_config,
)


class FakeResponse:
    def __init__(self, payload: dict[str, object] | str) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        if isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload).encode("utf-8")


class FakeOpener:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses

    def open(self, request: object, timeout: int) -> FakeResponse:
        return self.responses.pop(0)


class PolicyTests(unittest.TestCase):
    def test_default_policy_contains_requested_region_rules(self) -> None:
        config = GuardConfig().normalized()
        self.assertEqual("combined", config.policy_mode)
        self.assertEqual(2, config.config_version)
        self.assertEqual("auto", config.ip_query_network_mode)
        self.assertEqual(1, config.check_interval_seconds)
        self.assertEqual(600, config.cache_ttl_seconds)
        self.assertTrue(config.clash_required)
        self.assertIn("mihomo.exe", config.clash_process_names)
        self.assertIn("v2rayn.exe", config.clash_process_names)
        self.assertIn("sing-box.exe", config.clash_process_names)
        self.assertIn("wireguard.exe", config.clash_process_names)
        self.assertIn(1080, config.clash_proxy_ports)
        self.assertIn(7897, config.clash_proxy_ports)
        self.assertIn(10808, config.clash_proxy_ports)
        self.assertIn("https://claude.ai/cdn-cgi/trace", config.providers)
        self.assertIn("https://api.anthropic.com/cdn-cgi/trace", config.providers)
        self.assertEqual(["US"], config.allowed_country_codes)
        self.assertEqual(
            ["CN", "CU", "HK", "IR", "KP", "MO", "RU", "SY"],
            config.blocked_country_codes,
        )

    def test_allowlist_mode_ignores_blacklist_fields(self) -> None:
        config = GuardConfig(
            policy_mode="allowlist",
            allowed_country_codes=["US"],
            blocked_country_codes=["US"],
            blocked_ip_networks=["8.8.8.0/24"],
        ).normalized()
        self.assertTrue(evaluate_policy(IpInfo("8.8.8.8", "US"), config).compliant)

    def test_blocklist_mode_ignores_allowlist(self) -> None:
        config = GuardConfig(
            policy_mode="blocklist",
            allowed_country_codes=["US"],
            blocked_country_codes=["CN"],
        ).normalized()
        self.assertTrue(evaluate_policy(IpInfo("1.1.1.1", "AU"), config).compliant)
        self.assertFalse(evaluate_policy(IpInfo("1.0.1.1", "CN"), config).compliant)

    def test_invalid_policy_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "policy_mode"):
            GuardConfig(policy_mode="unknown").normalized()

    def test_invalid_network_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ip_query_network_mode"):
            GuardConfig(ip_query_network_mode="unknown").normalized()

    def test_auto_network_mode_follows_actual_proxy_type(self) -> None:
        config = GuardConfig(ip_query_network_mode="auto").normalized()
        self.assertEqual(
            "system_proxy",
            resolve_ip_query_network_mode(
                config,
                ClashStatus(True, proxy_endpoints=("127.0.0.1:7890",)),
            ),
        )
        self.assertEqual(
            "direct",
            resolve_ip_query_network_mode(
                config,
                ClashStatus(True, tun_interfaces=("WireGuard Tunnel",)),
            ),
        )
        self.assertEqual(
            "direct",
            resolve_ip_query_network_mode(config, ClashStatus(False)),
        )
        self.assertEqual(
            "direct",
            resolve_ip_query_network_mode(config, ClashStatus(None)),
        )

    def test_manual_network_modes_are_preserved(self) -> None:
        active = ClashStatus(True)
        direct = GuardConfig(ip_query_network_mode="direct").normalized()
        proxy = GuardConfig(ip_query_network_mode="system_proxy").normalized()
        self.assertEqual("direct", resolve_ip_query_network_mode(direct, active))
        self.assertEqual("system_proxy", resolve_ip_query_network_mode(proxy, active))

    def test_legacy_default_direct_config_is_migrated_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"ip_query_network_mode": "direct"}', encoding="utf-8")
            config = load_config(path)
            persisted = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("auto", config.ip_query_network_mode)
        self.assertEqual(2, persisted["config_version"])
        self.assertEqual("auto", persisted["ip_query_network_mode"])

    def test_versioned_manual_direct_config_is_not_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                '{"config_version": 2, "ip_query_network_mode": "direct"}',
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual("direct", config.ip_query_network_mode)

    def test_allowed_country_passes(self) -> None:
        config = GuardConfig(allowed_country_codes=["us"]).normalized()
        result = evaluate_policy(IpInfo("8.8.8.8", "US"), config)
        self.assertTrue(result.compliant)

    def test_country_outside_allowlist_is_blocked(self) -> None:
        config = GuardConfig(allowed_country_codes=["US"]).normalized()
        result = evaluate_policy(IpInfo("1.1.1.1", "AU"), config)
        self.assertFalse(result.compliant)
        self.assertIn("不在白名单", result.reason)

    def test_country_blacklist_takes_precedence(self) -> None:
        config = GuardConfig(
            allowed_country_codes=["US"], blocked_country_codes=["US"]
        ).normalized()
        result = evaluate_policy(IpInfo("8.8.8.8", "US"), config)
        self.assertFalse(result.compliant)
        self.assertIn("黑名单", result.reason)

    def test_cidr_blacklist_blocks_address(self) -> None:
        config = GuardConfig(
            allowed_country_codes=[], blocked_ip_networks=["8.8.8.0/24"]
        ).normalized()
        result = evaluate_policy(IpInfo("8.8.8.8", "US"), config)
        self.assertFalse(result.compliant)
        self.assertIn("8.8.8.0/24", result.reason)


class SwitchingGeoLookup(GeoLookup):
    COUNTRY_BY_IP = {
        "8.8.8.8": ("US", "United States"),
        "1.1.1.1": ("AU", "Australia"),
    }

    def __init__(self) -> None:
        super().__init__()
        self.current_ip = "8.8.8.8"
        self.ip_query_count = 0
        self.geo_query_count: dict[str, int] = {}
        self.count_lock = threading.Lock()

    def _lookup_provider(
        self,
        url: str,
        timeout: int,
        expected_ip: str = "",
        network_mode: str = "direct",
    ) -> IpInfo:
        if "current.example" in url:
            with self.count_lock:
                self.ip_query_count += 1
            code, name = self.COUNTRY_BY_IP[self.current_ip]
            return IpInfo(self.current_ip, code, name, provider=url)
        if "geo.example" in url:
            with self.count_lock:
                self.geo_query_count[expected_ip] = self.geo_query_count.get(expected_ip, 0) + 1
            time.sleep(0.03)
            code, name = self.COUNTRY_BY_IP[expected_ip]
            return IpInfo(expected_ip, code, name, provider=url)
        raise ValueError(f"unexpected provider: {url}")


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = GuardConfig(
            cache_ttl_seconds=600,
            providers=["https://current.example/ip"],
            geo_providers=["https://geo.example/{ip}"],
        ).normalized()

    def test_same_ip_requeries_current_ip_but_reuses_geo_cache(self) -> None:
        lookup = SwitchingGeoLookup()
        first = lookup.lookup_all(self.config)
        second = lookup.lookup_all(self.config)
        self.assertEqual(first, second)
        self.assertEqual(2, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 1}, lookup.geo_query_count)

    def test_ip_change_is_detected_immediately(self) -> None:
        lookup = SwitchingGeoLookup()
        first = lookup.lookup_all(self.config)
        lookup.current_ip = "1.1.1.1"
        second = lookup.lookup_all(self.config)
        self.assertEqual("8.8.8.8", first[0].ip)
        self.assertEqual("1.1.1.1", second[0].ip)
        self.assertEqual("AU", second[0].country_code)
        self.assertEqual(2, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 1, "1.1.1.1": 1}, lookup.geo_query_count)

    def test_switching_back_uses_that_ips_own_cached_geo(self) -> None:
        lookup = SwitchingGeoLookup()
        lookup.lookup_all(self.config)
        lookup.current_ip = "1.1.1.1"
        lookup.lookup_all(self.config)
        lookup.current_ip = "8.8.8.8"
        result = lookup.lookup_all(self.config)
        self.assertEqual("8.8.8.8", result[0].ip)
        self.assertEqual("US", result[0].country_code)
        self.assertEqual(3, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 1, "1.1.1.1": 1}, lookup.geo_query_count)

    def test_expired_geo_cache_is_refreshed(self) -> None:
        lookup = SwitchingGeoLookup()
        clock = [100.0]
        with patch("ip_guard.core.time.monotonic", side_effect=lambda: clock[0]):
            lookup.lookup_all(self.config)
            clock[0] = 699.0
            lookup.lookup_all(self.config)
            self.assertEqual({"8.8.8.8": 1}, lookup.geo_query_count)
            clock[0] = 701.0
            lookup.lookup_all(self.config)
        self.assertEqual(3, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 2}, lookup.geo_query_count)

    def test_force_refresh_bypasses_only_geo_cache(self) -> None:
        lookup = SwitchingGeoLookup()
        lookup.lookup_all(self.config)
        lookup.lookup_all(self.config, force_refresh=True)
        self.assertEqual(2, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 2}, lookup.geo_query_count)

    def test_zero_ttl_disables_geo_cache(self) -> None:
        lookup = SwitchingGeoLookup()
        self.config.cache_ttl_seconds = 0
        lookup.lookup_all(self.config)
        lookup.lookup_all(self.config)
        self.assertEqual(2, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 2}, lookup.geo_query_count)

    def test_clear_cache_forces_next_geo_query(self) -> None:
        lookup = SwitchingGeoLookup()
        lookup.lookup_all(self.config)
        lookup.clear_cache()
        lookup.lookup_all(self.config)
        self.assertEqual(2, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 2}, lookup.geo_query_count)

    def test_concurrent_checks_each_query_ip_but_share_geo_cache(self) -> None:
        lookup = SwitchingGeoLookup()
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: lookup.lookup_all(self.config), range(8)))
        self.assertEqual(8, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 1}, lookup.geo_query_count)
        self.assertTrue(all(result == results[0] for result in results))

    def test_duplicate_ip_from_multiple_sources_is_geolocated_once(self) -> None:
        lookup = SwitchingGeoLookup()
        self.config.providers = [
            "https://current.example/one",
            "https://current.example/two",
            "https://current.example/three",
        ]
        result = lookup.lookup_all(self.config)
        self.assertEqual(3, len(result))
        self.assertEqual(3, lookup.ip_query_count)
        self.assertEqual({"8.8.8.8": 1}, lookup.geo_query_count)


class ProviderTests(unittest.TestCase):
    @patch("ip_guard.core.get_system_proxies")
    @patch("urllib.request.build_opener")
    def test_direct_mode_bypasses_environment_and_system_proxies(
        self,
        build_opener: object,
        system_proxies: object,
    ) -> None:
        build_opener.return_value = FakeOpener([  # type: ignore[attr-defined]
            FakeResponse({"ip": "101.204.146.190", "country_code": "CN"})
        ])
        info = GeoLookup()._lookup_provider(
            "https://ipwho.is/",
            8,
            network_mode="direct",
        )
        self.assertEqual("101.204.146.190", info.ip)
        system_proxies.assert_not_called()  # type: ignore[attr-defined]
        handler = build_opener.call_args.args[0]  # type: ignore[attr-defined]
        self.assertEqual({}, handler.proxies)

    @patch("urllib.request.build_opener")
    def test_skk_ip_is_enriched_by_net_coffee(self, build_opener: object) -> None:
        build_opener.return_value = FakeOpener([  # type: ignore[attr-defined]
            FakeResponse({"ip": "8.8.8.8", "country": "US"}),
            FakeResponse(
                {
                    "country": "United States",
                    "country_code": "us",
                    "region": "California",
                }
            ),
        ])
        config = GuardConfig(
            claude_route_checks_enabled=False,
            ip_query_network_mode="direct",
            providers=["https://ip.api.skk.moe/v1/ipinfo-simple"],
            geo_providers=["https://ip.net.coffee/api/geoip/{ip}"],
        ).normalized()
        info = GeoLookup().lookup(config)
        self.assertEqual("8.8.8.8", info.ip)
        self.assertEqual("US", info.country_code)
        self.assertEqual("United States", info.country_name)
        self.assertIn("ip.net.coffee", info.provider)

    @patch("ip_guard.core.get_system_proxies")
    @patch("urllib.request.build_opener")
    def test_each_check_rebuilds_opener_with_current_system_proxy(
        self,
        build_opener: object,
        system_proxies: object,
    ) -> None:
        build_opener.side_effect = [  # type: ignore[attr-defined]
            FakeOpener([FakeResponse({"ip": "8.8.8.8", "country_code": "US"})]),
            FakeOpener([FakeResponse({"ip": "1.1.1.1", "country_code": "AU"})]),
        ]
        system_proxies.side_effect = [  # type: ignore[attr-defined]
            {"https": "http://127.0.0.1:10001"},
            {"https": "http://127.0.0.1:10002"},
        ]
        config = GuardConfig(
            claude_route_checks_enabled=False,
            ip_query_network_mode="system_proxy",
            providers=["https://current.example/ip"],
            geo_providers=[],
        ).normalized()
        lookup = GeoLookup()
        first = lookup.lookup_all(config)
        second = lookup.lookup_all(config)
        self.assertEqual("8.8.8.8", first[0].ip)
        self.assertEqual("1.1.1.1", second[0].ip)
        self.assertEqual(2, build_opener.call_count)  # type: ignore[attr-defined]
        self.assertEqual(2, system_proxies.call_count)  # type: ignore[attr-defined]

    @patch("urllib.request.getproxies", return_value={"https": "http://env:9999"})
    @patch(
        "urllib.request.getproxies_registry",
        return_value={"https": "http://127.0.0.1:7890"},
    )
    @patch("ip_guard.core.platform.system", return_value="Windows")
    def test_windows_system_proxy_ignores_environment_variables(
        self,
        platform_system: object,
        registry_proxies: object,
        environment_proxies: object,
    ) -> None:
        self.assertEqual(
            {"https": "http://127.0.0.1:7890"},
            get_system_proxies(),
        )
        registry_proxies.assert_called_once_with()  # type: ignore[attr-defined]
        environment_proxies.assert_not_called()  # type: ignore[attr-defined]

    @patch("urllib.request.build_opener")
    def test_cloudflare_trace_response_is_supported(self, build_opener: object) -> None:
        build_opener.return_value = FakeOpener([  # type: ignore[attr-defined]
            FakeResponse("fl=1\nip=1.1.1.1\nloc=AU\ntls=TLSv1.3\n")
        ])
        info = GeoLookup()._lookup_provider("https://claude.ai/cdn-cgi/trace", 8)
        self.assertEqual("1.1.1.1", info.ip)
        self.assertEqual("AU", info.country_code)


class ClashDetectorTests(unittest.TestCase):
    def test_no_matching_process_or_proxy_signal_is_inactive(self) -> None:
        detector = ClashDetector()
        with (
            patch.object(detector, "_find_processes", return_value=()),
            patch.object(detector, "_system_proxy_endpoints", return_value=()),
            patch.object(detector, "_active_tun_interfaces", return_value=()),
        ):
            status = detector.detect(GuardConfig().normalized())
        self.assertFalse(status.active)
        self.assertIn("均未启用", status.reason)

    def test_running_process_and_listener_only_is_inactive(self) -> None:
        detector = ClashDetector()
        with (
            patch.object(detector, "_find_processes", return_value=((101, "mihomo.exe"),)),
            patch.object(detector, "_find_owned_listeners", return_value=("127.0.0.1:7890",)),
            patch.object(detector, "_system_proxy_endpoints", return_value=()),
            patch.object(detector, "_active_tun_interfaces", return_value=()),
        ):
            status = detector.detect(GuardConfig().normalized())
        self.assertFalse(status.active)
        self.assertEqual((), status.proxy_endpoints)
        self.assertEqual(("127.0.0.1:7890",), status.listening_endpoints)
        self.assertIn("仅发现监听端口", status.reason)

    def test_reachable_system_proxy_is_active_without_known_process(self) -> None:
        detector = ClashDetector()
        with (
            patch.object(detector, "_find_processes", return_value=()),
            patch.object(detector, "_system_proxy_endpoints", return_value=("127.0.0.1:10808",)),
            patch.object(detector, "_endpoint_reachable", return_value=True),
            patch.object(detector, "_active_tun_interfaces", return_value=()),
        ):
            status = detector.detect(GuardConfig().normalized())
        self.assertTrue(status.active)
        self.assertEqual(("127.0.0.1:10808",), status.proxy_endpoints)
        self.assertIn("未匹配到已配置进程名", status.reason)

    def test_running_process_without_proxy_signal_is_inactive(self) -> None:
        detector = ClashDetector()
        with (
            patch.object(detector, "_find_processes", return_value=((101, "clash-verge.exe"),)),
            patch.object(detector, "_find_owned_listeners", return_value=()),
            patch.object(detector, "_system_proxy_endpoints", return_value=()),
            patch.object(detector, "_active_tun_interfaces", return_value=()),
        ):
            status = detector.detect(GuardConfig().normalized())
        self.assertFalse(status.active)
        self.assertIn("均未启用", status.reason)

    def test_running_process_and_tun_is_active(self) -> None:
        detector = ClashDetector()
        with (
            patch.object(detector, "_find_processes", return_value=((101, "mihomo.exe"),)),
            patch.object(detector, "_find_owned_listeners", return_value=()),
            patch.object(detector, "_system_proxy_endpoints", return_value=()),
            patch.object(detector, "_active_tun_interfaces", return_value=("Mihomo",)),
        ):
            status = detector.detect(GuardConfig().normalized())
        self.assertTrue(status.active)
        self.assertEqual(("Mihomo",), status.tun_interfaces)


    def test_tun_evidence_still_passes_when_listener_inspection_fails(self) -> None:
        detector = ClashDetector()
        with (
            patch.object(detector, "_find_processes", return_value=((101, "mihomo.exe"),)),
            patch.object(detector, "_find_owned_listeners", side_effect=PermissionError("denied")),
            patch.object(detector, "_system_proxy_endpoints", return_value=()),
            patch.object(detector, "_active_tun_interfaces", return_value=("Mihomo",)),
        ):
            status = detector.detect(GuardConfig().normalized())
        self.assertTrue(status.active)
        self.assertEqual(("Mihomo",), status.tun_interfaces)

    def test_no_evidence_with_detection_error_is_unknown(self) -> None:
        detector = ClashDetector()
        with (
            patch.object(detector, "_find_processes", return_value=((101, "mihomo.exe"),)),
            patch.object(detector, "_find_owned_listeners", side_effect=PermissionError("denied")),
            patch.object(detector, "_system_proxy_endpoints", return_value=()),
            patch.object(detector, "_active_tun_interfaces", return_value=()),
        ):
            status = detector.detect(GuardConfig().normalized())
        self.assertIsNone(status.active)
        self.assertIn("无法确认", status.reason)


class FakeLookup:
    def __init__(self, value: IpInfo | Exception) -> None:
        self.value = value

    def lookup(self, config: GuardConfig) -> IpInfo:
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class CapturingLookup:
    def __init__(self) -> None:
        self.network_modes: list[str] = []

    def lookup(self, config: GuardConfig) -> IpInfo:
        self.network_modes.append(config.ip_query_network_mode)
        return IpInfo("8.8.8.8", "US")


class FakeMultiLookup:
    def lookup_all(self, config: GuardConfig, force_refresh: bool = False) -> tuple[IpInfo, ...]:
        return (IpInfo("8.8.8.8", "US"), IpInfo("1.1.1.1", "AU"))


class FakeClashDetector:
    def __init__(self, status: ClashStatus) -> None:
        self.status = status

    def detect(self, config: GuardConfig) -> ClashStatus:
        return self.status


class FakeTerminator:
    def __init__(self) -> None:
        self.calls = 0

    def terminate_named(self, process_names: list[str]) -> tuple[int, ...]:
        self.calls += 1
        return (42,)


class ServiceTests(unittest.TestCase):
    def test_auto_mode_uses_system_proxy_when_clash_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lookup = CapturingLookup()
            service = GuardService(
                self._config_path(directory),
                lookup=lookup,  # type: ignore[arg-type]
                clash_detector=FakeClashDetector(
                    ClashStatus(
                        True,
                        proxy_endpoints=("127.0.0.1:7890",),
                        reason="系统代理已启用",
                    )
                ),  # type: ignore[arg-type]
            )
            result = service.check_once(enforce=False)
        self.assertEqual(["system_proxy"], lookup.network_modes)
        self.assertIn("自动选择 系统代理出口", result.message)

    def test_auto_mode_uses_direct_when_clash_is_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lookup = CapturingLookup()
            service = GuardService(
                self._config_path(directory),
                lookup=lookup,  # type: ignore[arg-type]
                clash_detector=FakeClashDetector(ClashStatus(False, reason="Clash 已关闭")),  # type: ignore[arg-type]
            )
            result = service.check_once(enforce=False)
        self.assertEqual(["direct"], lookup.network_modes)
        self.assertIn("自动选择 本机直连", result.message)

    def test_any_noncompliant_provider_result_invokes_terminator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            terminator = FakeTerminator()
            service = GuardService(
                self._config_path(directory),
                lookup=FakeMultiLookup(),  # type: ignore[arg-type]
                terminator=terminator,  # type: ignore[arg-type]
            )
            result = service.check_once()
            self.assertFalse(result.compliant)
            self.assertEqual(1, terminator.calls)
            self.assertIn("US@8.8.8.8", result.message)
            self.assertIn("AU@1.1.1.1", result.message)

    def _config_path(
        self,
        directory: str,
        fail_closed: bool = False,
        clash_required: bool = False,
    ) -> Path:
        path = Path(directory) / "config.json"
        save_config(
            path,
            GuardConfig(fail_closed=fail_closed, clash_required=clash_required),
        )
        return path

    def test_compliant_ip_is_blocked_when_clash_is_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            terminator = FakeTerminator()
            service = GuardService(
                self._config_path(directory, clash_required=True),
                lookup=FakeLookup(IpInfo("8.8.8.8", "US")),  # type: ignore[arg-type]
                terminator=terminator,  # type: ignore[arg-type]
                clash_detector=FakeClashDetector(
                    ClashStatus(False, reason="未检测到 Clash/Mihomo 进程")
                ),  # type: ignore[arg-type]
            )
            result = service.check_once()
            self.assertFalse(result.compliant)
            self.assertEqual(1, terminator.calls)
            self.assertIn("未检测到 Clash", result.message)
            self.assertIn("US@8.8.8.8", result.message)

    def test_clash_and_compliant_ip_pass_joint_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            terminator = FakeTerminator()
            service = GuardService(
                self._config_path(directory, clash_required=True),
                lookup=FakeLookup(IpInfo("8.8.8.8", "US")),  # type: ignore[arg-type]
                terminator=terminator,  # type: ignore[arg-type]
                clash_detector=FakeClashDetector(
                    ClashStatus(
                        True,
                        running_processes=("mihomo.exe",),
                        proxy_endpoints=("127.0.0.1:7890",),
                        reason="Clash/Mihomo 已运行",
                    )
                ),  # type: ignore[arg-type]
            )
            result = service.check_once()
            self.assertTrue(result.compliant)
            self.assertEqual(0, terminator.calls)
            self.assertIn("联合检查通过", result.message)

    def test_inactive_clash_still_blocks_when_ip_lookup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            terminator = FakeTerminator()
            service = GuardService(
                self._config_path(directory, clash_required=True),
                lookup=FakeLookup(RuntimeError("offline")),  # type: ignore[arg-type]
                terminator=terminator,  # type: ignore[arg-type]
                clash_detector=FakeClashDetector(
                    ClashStatus(False, reason="Clash 未启用")
                ),  # type: ignore[arg-type]
            )
            result = service.check_once()
            self.assertFalse(result.compliant)
            self.assertEqual(1, terminator.calls)
            self.assertIn("IP 查询失败", result.message)

    def test_noncompliant_result_invokes_terminator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            terminator = FakeTerminator()
            service = GuardService(
                self._config_path(directory),
                lookup=FakeLookup(IpInfo("1.1.1.1", "AU")),  # type: ignore[arg-type]
                terminator=terminator,  # type: ignore[arg-type]
            )
            result = service.check_once()
            self.assertFalse(result.compliant)
            self.assertEqual(1, terminator.calls)
            self.assertEqual((42,), result.terminated_pids)

    def test_lookup_failure_is_fail_open_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            terminator = FakeTerminator()
            service = GuardService(
                self._config_path(directory),
                lookup=FakeLookup(RuntimeError("offline")),  # type: ignore[arg-type]
                terminator=terminator,  # type: ignore[arg-type]
            )
            result = service.check_once()
            self.assertIsNone(result.compliant)
            self.assertEqual(0, terminator.calls)

    def test_lookup_failure_can_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            terminator = FakeTerminator()
            service = GuardService(
                self._config_path(directory, fail_closed=True),
                lookup=FakeLookup(RuntimeError("offline")),  # type: ignore[arg-type]
                terminator=terminator,  # type: ignore[arg-type]
            )
            result = service.check_once()
            self.assertIsNone(result.compliant)
            self.assertEqual(1, terminator.calls)


class FakeProcess:
    def __init__(self, pid: int, name: str) -> None:
        self.pid = pid
        self.info = {"pid": pid, "name": name, "exe": None}
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True


class ProcessTests(unittest.TestCase):
    @patch("psutil.wait_procs", return_value=([], []))
    @patch("psutil.process_iter")
    def test_only_exact_process_names_are_terminated(self, process_iter: object, wait_procs: object) -> None:
        current = FakeProcess(os.getpid(), "kiro.exe")
        target = FakeProcess(10001, "kiro.exe")
        unrelated = FakeProcess(10002, "my-kiro-helper.exe")
        process_iter.return_value = [current, target, unrelated]  # type: ignore[attr-defined]

        result = ProcessTerminator().terminate_named(["kiro.exe"])

        self.assertEqual((10001,), result)
        self.assertTrue(target.terminated)
        self.assertFalse(current.terminated)
        self.assertFalse(unrelated.terminated)


if __name__ == "__main__":
    unittest.main()
