from __future__ import annotations

import ipaddress
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from ip_guard.core import (
    ClashStatus,
    GeoLookup,
    GuardConfig,
    GuardService,
    IpInfo,
    StunObservation,
    save_config,
    stun_socks_candidates,
)
from ip_guard.settings import config_from_form
from ip_guard.stun import (
    MAGIC_COOKIE,
    normalize_stun_server,
    parse_binding_response,
    parse_socks_proxy,
    probe_socks5_udp,
    stun_binding,
)


def binding_response(transaction_id: bytes, address: str, xor: bool = True) -> bytes:
    ip = ipaddress.ip_address(address)
    raw = ip.packed
    if xor:
        key = struct.pack("!I", MAGIC_COOKIE) + transaction_id
        raw = bytes(byte ^ key[index] for index, byte in enumerate(raw))
    family = 1 if ip.version == 4 else 2
    value = struct.pack("!BBH", 0, family, 0) + raw
    attribute = struct.pack("!HH", 0x0020 if xor else 0x0001, len(value)) + value
    return struct.pack("!HHI", 0x0101, len(attribute), MAGIC_COOKIE) + transaction_id + attribute


class FakeStunServer:
    """Answers Binding Requests on 127.0.0.1 with a fixed mapped address."""

    def __init__(self, mapped: str, drop_first: bool = False) -> None:
        self.mapped = mapped
        self.drop_first = drop_first
        self.requests = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                data, address = self.sock.recvfrom(2048)
            except OSError:
                return
            self.requests += 1
            if self.drop_first and self.requests == 1:
                continue  # Simulate a lost packet; the client must retransmit.
            self.sock.sendto(binding_response(data[8:20], self.mapped), address)

    def close(self) -> None:
        self.sock.close()


class FakeSocks5Proxy:
    """Minimal SOCKS5 server supporting UDP ASSOCIATE for one STUN target."""

    def __init__(self, mapped: str, probe_only: bool = False) -> None:
        self.mapped = mapped
        self.probe_only = probe_only
        self.targets: list[tuple[str, int]] = []
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.relay.bind(("127.0.0.1", 0))
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        connection, _ = self.listener.accept()
        with connection:
            connection.recv(3)
            connection.sendall(b"\x05\x00")
            connection.recv(10)
            # Reply with 0.0.0.0 like Clash; the client must use the proxy host.
            relay_port = self.relay.getsockname()[1]
            connection.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + struct.pack("!H", relay_port))
            if self.probe_only:
                return
            data, address = self.relay.recvfrom(2048)
            assert data[3] == 3, "client should send the domain name"
            size = data[4]
            host = data[5 : 5 + size].decode()
            port = struct.unpack("!H", data[5 + size : 7 + size])[0]
            self.targets.append((host, port))
            request = data[7 + size :]
            header = b"\x00\x00\x00\x01" + socket.inet_aton("1.2.3.4") + struct.pack("!H", port)
            self.relay.sendto(header + binding_response(request[8:20], self.mapped), address)
            connection.recv(1)  # Keep the association open until the client closes.

    def close(self) -> None:
        self.listener.close()
        self.relay.close()


class StunProtocolTests(unittest.TestCase):
    def test_xor_mapped_ipv4_and_ipv6_are_decoded(self) -> None:
        tid = bytes(range(12))
        self.assertEqual("104.251.229.180", parse_binding_response(binding_response(tid, "104.251.229.180"), tid))
        self.assertEqual("2606:4700::1", parse_binding_response(binding_response(tid, "2606:4700::1"), tid))
        self.assertEqual("8.8.8.8", parse_binding_response(binding_response(tid, "8.8.8.8", xor=False), tid))

    def test_response_for_another_transaction_is_ignored(self) -> None:
        response = binding_response(b"a" * 12, "8.8.8.8")
        self.assertIsNone(parse_binding_response(response, b"b" * 12))

    def test_error_response_is_rejected(self) -> None:
        tid = b"c" * 12
        error = struct.pack("!HHI", 0x0111, 0, MAGIC_COOKIE) + tid
        with self.assertRaisesRegex(ValueError, "错误响应"):
            parse_binding_response(error, tid)

    def test_direct_binding_retransmits_after_loss(self) -> None:
        server = FakeStunServer("104.251.229.180", drop_first=True)
        self.addCleanup(server.close)
        self.assertEqual("104.251.229.180", stun_binding("127.0.0.1", server.port, 5))
        self.assertGreaterEqual(server.requests, 2)

    def test_direct_binding_times_out(self) -> None:
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        self.addCleanup(silent.close)
        with self.assertRaises(TimeoutError):
            stun_binding("127.0.0.1", silent.getsockname()[1], 1)

    def test_binding_through_socks5_udp_relay(self) -> None:
        proxy = FakeSocks5Proxy("104.251.229.180")
        self.addCleanup(proxy.close)
        result = stun_binding("stun.cloudflare.com", 3478, 5, ("127.0.0.1", proxy.port))
        self.assertEqual("104.251.229.180", result)
        self.assertEqual([("stun.cloudflare.com", 3478)], proxy.targets)

    def test_server_address_formats(self) -> None:
        self.assertEqual("stun.cloudflare.com:3478", normalize_stun_server("stun.cloudflare.com"))
        self.assertEqual("stun.l.google.com:19302", normalize_stun_server("stun:stun.l.google.com:19302"))
        self.assertEqual("[2606:4700::1]:3478", normalize_stun_server("[2606:4700::1]"))
        self.assertEqual(("127.0.0.1", 10808), parse_socks_proxy("socks5://127.0.0.1:10808"))
        for bad in ("", "host:99999", "https://example.com/x", "host:abc"):
            with self.assertRaises(ValueError):
                normalize_stun_server(bad)
        with self.assertRaises(ValueError):
            parse_socks_proxy("127.0.0.1")  # SOCKS port is required.


class StunConfigTests(unittest.TestCase):
    def test_defaults_are_cloudflare_and_disabled(self) -> None:
        config = GuardConfig().normalized()
        self.assertFalse(config.stun_enabled)
        self.assertEqual(["stun.cloudflare.com:3478"], config.stun_servers)
        self.assertEqual(["stun.cloudflare.com:3478"], config.stun_active_servers)
        self.assertEqual("", config.stun_socks_proxy)

    def test_active_servers_are_limited_to_configured_servers(self) -> None:
        config = GuardConfig(
            stun_servers=["stun.cloudflare.com", "stun:stun.l.google.com:19302"],
            stun_active_servers=["stun.l.google.com:19302", "unknown.example:3478"],
        ).normalized()
        self.assertEqual(["stun.cloudflare.com:3478", "stun.l.google.com:19302"], config.stun_servers)
        self.assertEqual(["stun.l.google.com:19302"], config.stun_active_servers)

    def test_no_active_server_falls_back_to_first(self) -> None:
        config = GuardConfig(stun_servers=["a.example:1"], stun_active_servers=[]).normalized()
        self.assertEqual(["a.example:1"], config.stun_active_servers)

    def test_form_requires_an_active_server(self) -> None:
        from test_settings import valid_form

        values = valid_form()
        values["stun_servers"] = "stun.cloudflare.com\nstun.l.google.com:19302"
        values["stun_active_servers"] = ""
        with self.assertRaisesRegex(ValueError, "STUN"):
            config_from_form(values)
        values["stun_active_servers"] = "stun.cloudflare.com:3478\nstun.l.google.com:19302"
        values["stun_enabled"] = True
        values["stun_socks_proxy"] = "127.0.0.1:10808"
        config = config_from_form(values)
        self.assertTrue(config.stun_enabled)
        self.assertEqual(2, len(config.stun_active_servers))
        self.assertEqual("127.0.0.1:10808", config.stun_socks_proxy)

    def test_form_rejects_invalid_socks_proxy(self) -> None:
        from test_settings import valid_form

        values = valid_form()
        values["stun_socks_proxy"] = "127.0.0.1"
        with self.assertRaisesRegex(ValueError, "SOCKS5"):
            config_from_form(values)

    @patch("ip_guard.core.get_system_proxies", return_value={"http": "http://127.0.0.1:10809"})
    def test_candidates_include_system_proxy_then_tool_ports(self, _proxies: object) -> None:
        status = ClashStatus(
            True,
            proxy_endpoints=("127.0.0.1:10809",),
            listening_endpoints=("127.0.0.1:10808", "127.0.0.1:10809"),
        )
        candidates = stun_socks_candidates(GuardConfig().normalized(), status)
        self.assertEqual(
            [("127.0.0.1", 10809), ("127.0.0.1", 10808)],
            [endpoint for endpoint, _ in candidates],
        )
        self.assertEqual(["系统代理", "代理工具监听端口"], [origin for _, origin in candidates])

    @patch("ip_guard.core.get_system_proxies", return_value={"http": "http://127.0.0.1:7890"})
    def test_manual_socks_endpoint_overrides_detection(self, _proxies: object) -> None:
        manual = GuardConfig(stun_socks_proxy="127.0.0.1:10808").normalized()
        status = ClashStatus(True, listening_endpoints=("127.0.0.1:7891",))
        self.assertEqual([("127.0.0.1", 10808)], [e for e, _ in stun_socks_candidates(manual, status)])

    @patch(
        "ip_guard.core.get_system_proxies",
        return_value={"http": "http://127.0.0.1:10809", "socks": "socks://127.0.0.1:10808"},
    )
    def test_system_socks_entry_is_preferred(self, _proxies: object) -> None:
        candidates = stun_socks_candidates(GuardConfig().normalized())
        self.assertEqual(("127.0.0.1", 10808), candidates[0][0])

    def test_probe_rejects_http_only_port(self) -> None:
        server = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(server.close)

        def answer_http() -> None:
            connection, _ = server.accept()
            with connection:
                connection.recv(16)
                connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")

        threading.Thread(target=answer_http, daemon=True).start()
        self.assertFalse(probe_socks5_udp(("127.0.0.1", server.getsockname()[1])))

    def test_probe_accepts_socks5_udp(self) -> None:
        proxy = FakeSocks5Proxy("104.251.229.180", probe_only=True)
        self.addCleanup(proxy.close)
        self.assertTrue(probe_socks5_udp(("127.0.0.1", proxy.port)))


class StunLookupTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.lookup = GeoLookup(Path(directory.name))
        self.config = GuardConfig(
            ip_query_network_mode="direct",
            geo_providers=[],
            stun_servers=["stun.cloudflare.com:3478", "stun.l.google.com:19302"],
            stun_active_servers=["stun.cloudflare.com:3478", "stun.l.google.com:19302"],
        ).normalized()

    def test_mapped_addresses_are_geolocated_locally(self) -> None:
        answers = {"stun.cloudflare.com": "104.251.229.180", "stun.l.google.com": TimeoutError("STUN 请求超时")}

        def fake_binding(host: str, port: int, timeout: float, via: object) -> str:
            self.assertIsNone(via)
            answer = answers[host]
            if isinstance(answer, Exception):
                raise answer
            return answer

        with (
            patch("ip_guard.core.stun_binding", side_effect=fake_binding),
            patch.object(self.lookup.local_db, "lookup", return_value=("JP", "Japan", Path("x.mmdb"))),
        ):
            result = self.lookup.lookup_stun(self.config)
        self.assertTrue(result[0].ok)
        self.assertEqual("JP", result[0].info.country_code)  # type: ignore[union-attr]
        self.assertEqual("local:x.mmdb", result[0].info.geo_provider)  # type: ignore[union-attr]
        self.assertEqual("", result[0].via)
        self.assertFalse(result[1].ok)
        self.assertIn("超时", result[1].error)

    @patch("ip_guard.core.probe_socks5_udp", return_value=True)
    @patch("ip_guard.core.get_system_proxies", return_value={"http": "http://127.0.0.1:7890"})
    def test_proxy_mode_uses_socks5_relay(self, _proxies: object, _probe: object) -> None:
        self.config.ip_query_network_mode = "system_proxy"
        with (
            patch("ip_guard.core.stun_binding", return_value="104.251.229.180") as binding,
            patch.object(self.lookup.local_db, "lookup", return_value=("JP", "Japan", Path("x.mmdb"))),
        ):
            result = self.lookup.lookup_stun(self.config)
        self.assertEqual(("127.0.0.1", 7890), binding.call_args.args[3])
        self.assertEqual("127.0.0.1:7890", result[0].via)
        self.assertEqual("系统代理", result[0].via_source)

    @patch("ip_guard.core.get_system_proxies", return_value={"http": "http://127.0.0.1:10809"})
    def test_http_only_system_proxy_falls_back_to_tool_socks_port(self, _proxies: object) -> None:
        # v2rayN style: system proxy is HTTP 10809, the tool also listens on SOCKS 10808.
        self.config.ip_query_network_mode = "system_proxy"
        status = ClashStatus(True, listening_endpoints=("127.0.0.1:10808", "127.0.0.1:10809"))
        probed: list[tuple[str, int]] = []

        def probe(endpoint: tuple[str, int]) -> bool:
            probed.append(endpoint)
            return endpoint[1] == 10808

        with (
            patch("ip_guard.core.probe_socks5_udp", side_effect=probe),
            patch("ip_guard.core.stun_binding", return_value="104.251.229.180") as binding,
            patch.object(self.lookup.local_db, "lookup", return_value=("JP", "Japan", Path("x.mmdb"))),
        ):
            result = self.lookup.lookup_stun(self.config, clash_status=status)
            self.assertEqual([("127.0.0.1", 10809), ("127.0.0.1", 10808)], probed)
            self.assertEqual(("127.0.0.1", 10808), binding.call_args.args[3])
            self.assertEqual("代理工具监听端口", result[0].via_source)
            # The working port is remembered and probed first next time.
            probed.clear()
            self.lookup.lookup_stun(self.config, clash_status=status)
            self.assertEqual([("127.0.0.1", 10808)], probed)

    @patch("ip_guard.core.probe_socks5_udp", return_value=False)
    @patch("ip_guard.core.get_system_proxies", return_value={"http": "http://127.0.0.1:10809"})
    def test_no_socks_capable_port_reports_tried_ports(self, _proxies: object, _probe: object) -> None:
        self.config.ip_query_network_mode = "system_proxy"
        with patch("ip_guard.core.stun_binding") as binding:
            result = self.lookup.lookup_stun(self.config)
        binding.assert_not_called()
        self.assertTrue(all(not item.ok for item in result))
        self.assertIn("127.0.0.1:10809", result[0].error)

    @patch("ip_guard.core.get_system_proxies", return_value={})
    def test_proxy_mode_without_endpoint_reports_error(self, _proxies: object) -> None:
        self.config.ip_query_network_mode = "system_proxy"
        with patch("ip_guard.core.stun_binding") as binding:
            result = self.lookup.lookup_stun(self.config)
        binding.assert_not_called()
        self.assertTrue(all(not item.ok for item in result))

    def test_private_mapped_address_is_rejected(self) -> None:
        with patch("ip_guard.core.stun_binding", return_value="198.18.0.5"):
            result = self.lookup.lookup_stun(self.config)
        self.assertFalse(result[0].ok)
        self.assertIsNone(result[0].info)

    def test_unknown_region_is_not_ok(self) -> None:
        with (
            patch("ip_guard.core.stun_binding", return_value="104.251.229.180"),
            patch.object(self.lookup.local_db, "lookup", return_value=None),
        ):
            result = self.lookup.lookup_stun(self.config)
        self.assertFalse(result[0].ok)
        self.assertEqual("104.251.229.180", result[0].info.ip)  # type: ignore[union-attr]


class StunServiceLookup:
    def __init__(self, observations: tuple[StunObservation, ...] | Exception) -> None:
        self.observations = observations
        self.stun_calls = 0

    def lookup_all(self, config: GuardConfig, force_refresh: bool = False) -> tuple[IpInfo, ...]:
        return (IpInfo("8.8.8.8", "US"),)

    def lookup_stun(
        self,
        config: GuardConfig,
        force_refresh: bool = False,
        clash_status: ClashStatus | None = None,
    ) -> tuple[StunObservation, ...]:
        self.stun_calls += 1
        self.clash_status = clash_status
        if isinstance(self.observations, Exception):
            raise self.observations
        return self.observations


class StunServiceTests(unittest.TestCase):
    def _service(self, directory: str, lookup: StunServiceLookup, enabled: bool) -> GuardService:
        from test_core import FakeClashDetector, FakeTerminator

        path = Path(directory) / "config.json"
        save_config(path, GuardConfig(clash_required=False, stun_enabled=enabled))
        self.terminator = FakeTerminator()
        return GuardService(
            path,
            lookup=lookup,  # type: ignore[arg-type]
            terminator=self.terminator,  # type: ignore[arg-type]
            clash_detector=FakeClashDetector(ClashStatus(False)),  # type: ignore[arg-type]
        )

    def test_disabled_stun_is_not_queried(self) -> None:
        lookup = StunServiceLookup(())
        with tempfile.TemporaryDirectory() as directory:
            result = self._service(directory, lookup, enabled=False).check_once()
        self.assertEqual(0, lookup.stun_calls)
        self.assertTrue(result.compliant)
        self.assertNotIn("STUN", result.message)

    def test_non_compliant_stun_egress_terminates(self) -> None:
        observation = StunObservation("stun.cloudflare.com:3478", info=IpInfo("171.217.43.88", "CN"))
        lookup = StunServiceLookup((observation,))
        with tempfile.TemporaryDirectory() as directory:
            result = self._service(directory, lookup, enabled=True).check_once()
        self.assertFalse(result.compliant)
        self.assertEqual(1, self.terminator.calls)
        self.assertIn("STUN stun.cloudflare.com:3478", result.message)
        self.assertEqual((observation,), result.stun_observations)
        # The service hands its proxy-tool detection to the STUN lookup.
        self.assertIsNotNone(lookup.clash_status)

    def test_compliant_stun_egress_passes(self) -> None:
        observation = StunObservation("stun.cloudflare.com:3478", info=IpInfo("104.251.229.180", "US"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._service(directory, StunServiceLookup((observation,)), enabled=True).check_once()
        self.assertTrue(result.compliant)
        self.assertIn("US@104.251.229.180", result.message)

    def test_all_stun_failures_are_unknown_not_terminated(self) -> None:
        observation = StunObservation("stun.cloudflare.com:3478", error="STUN 请求超时")
        with tempfile.TemporaryDirectory() as directory:
            result = self._service(directory, StunServiceLookup((observation,)), enabled=True).check_once()
        self.assertIsNone(result.compliant)
        self.assertEqual(0, self.terminator.calls)

    def test_stun_exception_keeps_monitor_alive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._service(directory, StunServiceLookup(RuntimeError("boom")), enabled=True).check_once()
        self.assertIsNone(result.compliant)


if __name__ == "__main__":
    unittest.main()
