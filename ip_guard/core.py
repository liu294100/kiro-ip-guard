from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

import psutil

from .i18n import SUPPORTED_LANGUAGES, effective_language, translate

LOG = logging.getLogger("kiro_ip_guard")

DEFAULT_PROVIDERS = (
    "https://ip.api.skk.moe/v1/ipinfo-simple",
    "https://ipwho.is/",
    "https://ipapi.co/json/",
)

CLAUDE_ROUTE_PROVIDERS = (
    "https://claude.ai/cdn-cgi/trace",
    "https://api.anthropic.com/cdn-cgi/trace",
)

DEFAULT_GEO_PROVIDERS = (
    "https://ip.net.coffee/api/geoip/{ip}",
)

POLICY_MODES = {"allowlist", "blocklist", "combined"}
NETWORK_MODES = {"auto", "direct", "system_proxy"}
DEFAULT_CLASH_PROCESS_NAMES = (
    "clash",
    "clash.exe",
    "clash-win64.exe",
    "clash-meta.exe",
    "clash-verge.exe",
    "clash-verge-rev.exe",
    "clash-verge-service.exe",
    "clash-nyanpasu.exe",
    "mihomo",
    "mihomo.exe",
    "mihomo-party.exe",
    "v2ray.exe",
    "v2rayn.exe",
    "xray.exe",
    "sing-box.exe",
    "shadowsocks.exe",
    "shadowsocks-win.exe",
    "shadowsocksr.exe",
    "hiddify.exe",
    "hiddify-next.exe",
    "nekoray.exe",
    "nekobox.exe",
    "qv2ray.exe",
    "trojan.exe",
    "trojan-go.exe",
    "wireguard.exe",
    "warp-svc.exe",
    "cloudflare warp.exe",
    "tailscale.exe",
    "tailscaled.exe",
)
DEFAULT_CLASH_PROXY_PORTS = (
    1080,
    2080,
    7890,
    7891,
    7892,
    7893,
    7897,
    8080,
    10808,
    10809,
    20170,
)
CLASH_TUN_KEYWORDS = (
    "clash",
    "mihomo",
    "wintun",
    "utun",
    "meta",
    "sing-box",
    "hiddify",
    "nekoray",
    "nekobox",
    "v2ray",
    "xray",
    "wireguard",
    "tailscale",
    "cloudflare warp",
)


@dataclass
class GuardConfig:
    config_version: int = 2
    enabled: bool = True
    policy_mode: str = "combined"
    ip_query_network_mode: str = "auto"
    language: str = "auto"
    check_updates: bool = True
    check_interval_seconds: int = 1
    cache_ttl_seconds: int = 600
    request_timeout_seconds: int = 8
    allowed_country_codes: list[str] = field(default_factory=lambda: ["US"])
    blocked_country_codes: list[str] = field(
        default_factory=lambda: ["CN", "CU", "HK", "IR", "KP", "MO", "RU", "SY"]
    )
    blocked_ip_networks: list[str] = field(default_factory=list)
    process_names: list[str] = field(
        default_factory=lambda: ["kiro", "kiro.exe", "kiro-cli", "kiro-cli.exe"]
    )
    fail_closed: bool = False
    clash_required: bool = True
    clash_process_names: list[str] = field(
        default_factory=lambda: list(DEFAULT_CLASH_PROCESS_NAMES)
    )
    clash_proxy_ports: list[int] = field(default_factory=lambda: list(DEFAULT_CLASH_PROXY_PORTS))
    claude_route_checks_enabled: bool = True
    providers: list[str] = field(default_factory=lambda: list(DEFAULT_PROVIDERS))
    geo_providers: list[str] = field(default_factory=lambda: list(DEFAULT_GEO_PROVIDERS))

    def normalized(self) -> "GuardConfig":
        self.config_version = max(2, int(self.config_version))
        self.policy_mode = str(self.policy_mode).strip().lower()
        if self.policy_mode not in POLICY_MODES:
            raise ValueError(
                translate(
                    self.language,
                    "policy_mode 必须是 allowlist、blocklist 或 combined，当前值: {value}",
                    value=self.policy_mode,
                )
            )
        self.ip_query_network_mode = str(self.ip_query_network_mode).strip().lower()
        if self.ip_query_network_mode not in NETWORK_MODES:
            raise ValueError(
                translate(
                    self.language,
                    "ip_query_network_mode 必须是 auto、direct 或 system_proxy，当前值: {value}",
                    value=self.ip_query_network_mode,
                )
            )
        self.language = str(self.language or "auto").strip()
        if self.language == "zh_CN":
            self.language = "zh-CN"
        if self.language not in SUPPORTED_LANGUAGES:
            raise ValueError("language must be auto, zh-CN, or en")
        self.check_updates = bool(self.check_updates)
        self.check_interval_seconds = max(1, int(self.check_interval_seconds))
        self.cache_ttl_seconds = max(0, int(self.cache_ttl_seconds))
        self.request_timeout_seconds = max(1, int(self.request_timeout_seconds))
        self.allowed_country_codes = _normalize_codes(self.allowed_country_codes)
        self.blocked_country_codes = _normalize_codes(self.blocked_country_codes)
        self.blocked_ip_networks = [str(value).strip() for value in self.blocked_ip_networks if str(value).strip()]
        self.process_names = [str(value).strip().lower() for value in self.process_names if str(value).strip()]
        self.clash_process_names = sorted(
            {str(value).strip().lower() for value in self.clash_process_names if str(value).strip()}
        )
        if not self.clash_process_names:
            self.clash_process_names = list(DEFAULT_CLASH_PROCESS_NAMES)
        try:
            self.clash_proxy_ports = sorted({int(value) for value in self.clash_proxy_ports})
        except (TypeError, ValueError) as exc:
            raise ValueError(
                translate(self.language, "clash_proxy_ports 必须全部是整数端口")
            ) from exc
        if any(port < 1 or port > 65535 for port in self.clash_proxy_ports):
            raise ValueError(translate(self.language, "clash_proxy_ports 必须位于 1～65535"))
        if not self.clash_proxy_ports:
            self.clash_proxy_ports = list(DEFAULT_CLASH_PROXY_PORTS)
        self.providers = [str(value).strip() for value in self.providers if str(value).strip()]
        self.geo_providers = [str(value).strip() for value in self.geo_providers if str(value).strip()]
        if not self.providers:
            self.providers = list(DEFAULT_PROVIDERS)
        if self.claude_route_checks_enabled:
            for provider in CLAUDE_ROUTE_PROVIDERS:
                if provider not in self.providers:
                    self.providers.append(provider)
        else:
            self.providers = [
                provider for provider in self.providers if provider not in CLAUDE_ROUTE_PROVIDERS
            ]
        if not self.providers:
            self.providers = list(DEFAULT_PROVIDERS)
        return self


@dataclass(frozen=True)
class IpInfo:
    ip: str
    country_code: str
    country_name: str = ""
    provider: str = ""


@dataclass(frozen=True)
class PolicyResult:
    compliant: bool
    reason: str


@dataclass(frozen=True)
class ClashStatus:
    active: Optional[bool]
    running_processes: tuple[str, ...] = ()
    proxy_endpoints: tuple[str, ...] = ()
    tun_interfaces: tuple[str, ...] = ()
    reason: str = ""
    listening_endpoints: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckResult:
    compliant: Optional[bool]
    message: str
    ip_info: Optional[IpInfo] = None
    terminated_pids: tuple[int, ...] = ()
    clash_status: Optional[ClashStatus] = None


def get_system_proxies() -> dict[str, str]:
    """Read OS proxy settings without treating environment variables as enabled on Windows."""
    if platform.system() == "Windows":
        registry_reader = getattr(urllib.request, "getproxies_registry", None)
        if registry_reader is not None:
            return dict(registry_reader())
    return dict(urllib.request.getproxies())


def resolve_ip_query_network_mode(config: GuardConfig, clash_status: ClashStatus) -> str:
    """Resolve auto mode without changing either manual compatibility mode."""
    if config.ip_query_network_mode != "auto":
        return config.ip_query_network_mode
    # A system proxy must use ProxyHandler. TUN/VPN routing is below HTTP and
    # still applies while direct mode explicitly ignores stale HTTP proxy data.
    return "system_proxy" if clash_status.proxy_endpoints else "direct"


def _normalize_codes(values: Iterable[str]) -> list[str]:
    return sorted({str(value).strip().upper() for value in values if str(value).strip()})


def default_config_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return root / "KiroIPGuard"
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "KiroIPGuard"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "kiro-ip-guard"


def load_config(path: Path) -> GuardConfig:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        config = GuardConfig().normalized()
        save_config(path, config)
        return config
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("配置根节点必须是 JSON 对象")
        # v1.3 and earlier wrote "direct" as the default. Migrate that legacy
        # default once so upgrades immediately gain automatic Clash routing.
        # Files saved by this version carry config_version=2, preserving an
        # explicit manual "direct" choice on subsequent loads.
        legacy_direct = (
            "config_version" not in data
            and data.get("ip_query_network_mode", "direct") == "direct"
        )
        if legacy_direct:
            data["ip_query_network_mode"] = "auto"
        known = GuardConfig.__dataclass_fields__.keys()
        config = GuardConfig(**{key: value for key, value in data.items() if key in known})
        config.normalized()
        if legacy_direct:
            save_config(path, config)
        return config
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"配置文件无效: {path}: {exc}") from exc


def save_config(path: Path, config: GuardConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(asdict(config.normalized()), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def evaluate_policy(info: IpInfo, config: GuardConfig) -> PolicyResult:
    language = config.language
    try:
        address = ipaddress.ip_address(info.ip)
    except ValueError:
        return PolicyResult(False, translate(language, "IP 地址格式无效: {ip}", ip=info.ip))

    if config.policy_mode in {"blocklist", "combined"}:
        for network_text in config.blocked_ip_networks:
            try:
                network = ipaddress.ip_network(network_text, strict=False)
            except ValueError:
                LOG.warning("忽略无效黑名单网段: %s", network_text)
                continue
            if address in network:
                return PolicyResult(
                    False,
                    translate(language, "IP {ip} 命中黑名单网段 {network}", ip=info.ip, network=network),
                )

    country_code = info.country_code.strip().upper()
    if not country_code:
        return PolicyResult(False, translate(language, "查询结果缺少国家/地区代码"))
    if config.policy_mode in {"blocklist", "combined"} and country_code in config.blocked_country_codes:
        return PolicyResult(
            False,
            translate(language, "国家/地区 {code} 位于黑名单", code=country_code),
        )
    if (
        config.policy_mode in {"allowlist", "combined"}
        and config.allowed_country_codes
        and country_code not in config.allowed_country_codes
    ):
        return PolicyResult(
            False,
            translate(
                language,
                "国家/地区 {code} 不在白名单 {allowed}",
                code=country_code,
                allowed=", ".join(config.allowed_country_codes),
            ),
        )
    return PolicyResult(True, translate(language, "国家/地区 {code} 符合策略", code=country_code))


class GeoLookup:
    def __init__(self) -> None:
        self._cache_lock = threading.RLock()
        self._geo_refresh_lock = threading.Lock()
        self._geo_cache: dict[tuple[object, ...], tuple[float, IpInfo]] = {}

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._geo_cache.clear()

    def lookup(self, config: GuardConfig, force_refresh: bool = False) -> IpInfo:
        return self.lookup_all(config, force_refresh=force_refresh)[0]

    def lookup_all(self, config: GuardConfig, force_refresh: bool = False) -> tuple[IpInfo, ...]:
        # The current public IP is intentionally never cached. Every policy check
        # asks every configured IP provider again so an egress change is detected.
        raw_results = self._query_current_ips(config)
        if not config.geo_providers:
            return raw_results

        first_by_ip: dict[str, IpInfo] = {}
        for info in raw_results:
            first_by_ip.setdefault(info.ip, info)

        geo_by_ip: dict[str, IpInfo | None] = {}
        workers = max(1, min(len(first_by_ip), 8))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="geo-provider") as executor:
            futures = {
                executor.submit(
                    self._lookup_geo_for_ip,
                    info.ip,
                    config,
                    force_refresh,
                ): info.ip
                for info in first_by_ip.values()
            }
            for future in as_completed(futures):
                ip = futures[future]
                geo_by_ip[ip] = future.result()

        return tuple(self._merge_geo(info, geo_by_ip.get(info.ip)) for info in raw_results)

    def _query_current_ips(self, config: GuardConfig) -> tuple[IpInfo, ...]:
        errors: list[str] = []
        results: dict[int, IpInfo] = {}
        workers = max(1, min(len(config.providers), 8))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ip-provider") as executor:
            futures = {
                executor.submit(
                    self._lookup_provider,
                    provider,
                    config.request_timeout_seconds,
                    "",
                    config.ip_query_network_mode,
                ): (index, provider)
                for index, provider in enumerate(config.providers)
            }
            for future in as_completed(futures):
                index, provider = futures[future]
                try:
                    results[index] = future.result()
                except Exception as exc:
                    errors.append(f"{provider}: {exc}")
                    LOG.warning("IP 查询服务失败: %s", errors[-1])
        if not results:
            raise RuntimeError("所有 IP 查询服务均失败: " + "; ".join(errors))
        return tuple(results[index] for index in sorted(results))

    def _lookup_geo_for_ip(
        self,
        ip: str,
        config: GuardConfig,
        force_refresh: bool,
    ) -> IpInfo | None:
        cache_key = (
            ip,
            config.ip_query_network_mode,
            tuple(config.geo_providers),
            config.request_timeout_seconds,
            config.cache_ttl_seconds,
        )
        if not force_refresh:
            cached = self._get_cached_geo(cache_key)
            if cached is not None:
                return cached

        with self._geo_refresh_lock:
            if not force_refresh:
                cached = self._get_cached_geo(cache_key)
                if cached is not None:
                    return cached
            for template in config.geo_providers:
                try:
                    url = template.format(ip=ip)
                    geo = self._lookup_provider(
                        url,
                        config.request_timeout_seconds,
                        expected_ip=ip,
                        network_mode=config.ip_query_network_mode,
                    )
                    if config.cache_ttl_seconds > 0:
                        with self._cache_lock:
                            self._geo_cache[cache_key] = (
                                time.monotonic() + config.cache_ttl_seconds,
                                geo,
                            )
                    return geo
                except (KeyError, OSError, ValueError, urllib.error.URLError) as exc:
                    LOG.warning("GeoIP 补充服务失败 %s: %s", template, exc)
        return None

    def _get_cached_geo(self, cache_key: tuple[object, ...]) -> IpInfo | None:
        with self._cache_lock:
            entry = self._geo_cache.get(cache_key)
            if entry is None:
                return None
            expires_at, info = entry
            if time.monotonic() < expires_at:
                return info
            self._geo_cache.pop(cache_key, None)
        return None

    @staticmethod
    def _merge_geo(original: IpInfo, geo: IpInfo | None) -> IpInfo:
        if geo is None:
            return original
        return IpInfo(
            ip=original.ip,
            country_code=geo.country_code,
            country_name=geo.country_name or original.country_name,
            provider=f"{original.provider} + {geo.provider}",
        )

    @staticmethod
    def _lookup_provider(
        url: str,
        timeout: int,
        expected_ip: str = "",
        network_mode: str = "direct",
    ) -> IpInfo:
        browser_platform = (
            "Macintosh; Intel Mac OS X 10_15_7"
            if platform.system() == "Darwin"
            else "Windows NT 10.0; Win64; x64"
        )
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Cache-Control": "no-cache, no-store",
            "Pragma": "no-cache",
            "User-Agent": (
                f"Mozilla/5.0 ({browser_platform}) "
                "AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
            ),
        }
        if ".skk.moe/" in url:
            headers.update({"Origin": "https://ip.skk.moe", "Referer": "https://ip.skk.moe/"})
        request = urllib.request.Request(url, headers=headers)
        if network_mode == "direct":
            # Explicitly bypass environment variables and OS HTTP(S) proxy
            # settings. VPN/TUN routes still apply because they are OS routes.
            proxy_handler = urllib.request.ProxyHandler({})
        elif network_mode == "system_proxy":
            # Re-read proxies on every request so changing a proxy line while
            # the guard is running takes effect for the next policy check.
            proxy_handler = urllib.request.ProxyHandler(get_system_proxies())
        else:
            raise ValueError(f"未知网络检测模式: {network_mode}")
        opener = urllib.request.build_opener(proxy_handler)
        with opener.open(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = {
                key.strip(): value.strip()
                for line in text.splitlines()
                if "=" in line
                for key, value in [line.split("=", 1)]
            }

        if payload.get("success") is False or payload.get("error") is True:
            raise ValueError(payload.get("message") or payload.get("reason") or "服务返回错误")
        ip = str(payload.get("ip") or expected_ip).strip()
        raw_country = str(payload.get("country") or "").strip()
        country_code = str(
            payload.get("country_code")
            or payload.get("countryCode")
            or payload.get("loc")
            or (raw_country if len(raw_country) == 2 else "")
        ).strip().upper()
        country_name = str(payload.get("country_name") or (raw_country if len(raw_country) != 2 else "")).strip()
        if not ip or not country_code:
            raise ValueError("响应缺少 ip 或 country_code")
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            raise ValueError(f"服务返回非公网 IP: {ip}")
        return IpInfo(ip=ip, country_code=country_code, country_name=country_name, provider=url)


class ClashDetector:
    """Detect whether a system proxy or TUN/VPN route is actually enabled."""

    def detect(self, config: GuardConfig) -> ClashStatus:
        errors: list[str] = []
        try:
            processes = self._find_processes(config.clash_process_names)
        except Exception as exc:
            LOG.warning("代理工具进程检测失败: %s", exc)
            processes = ()
            errors.append(f"进程: {exc}")

        pids = {pid for pid, _ in processes}
        process_names = tuple(sorted({name for _, name in processes}))
        try:
            owned_endpoints = (
                self._find_owned_listeners(pids, config.clash_proxy_ports) if pids else ()
            )
        except Exception as exc:
            LOG.warning("代理工具监听端口检测失败: %s", exc)
            owned_endpoints = ()
            errors.append(f"监听端口: {exc}")
        try:
            configured_system = self._system_proxy_endpoints()
            reachable_system = tuple(
                endpoint for endpoint in configured_system if self._endpoint_reachable(endpoint)
            )
        except Exception as exc:
            LOG.warning("系统代理检测失败: %s", exc)
            configured_system = ()
            reachable_system = ()
            errors.append(f"系统代理: {exc}")
        try:
            tun_interfaces = self._active_tun_interfaces()
        except Exception as exc:
            LOG.warning("TUN/VPN 网卡检测失败: %s", exc)
            tun_interfaces = ()
            errors.append(f"TUN/VPN: {exc}")

        # A listening core port alone does not mean traffic is using it. Only an
        # enabled, reachable OS proxy or an active TUN/VPN interface is evidence.
        has_evidence = bool(reachable_system or tun_interfaces)
        active: Optional[bool] = True if has_evidence else (None if errors else False)
        evidence: list[str] = []
        language = config.language
        if reachable_system:
            evidence.append(
                translate(language, "系统代理 {endpoints}", endpoints=", ".join(reachable_system))
            )
        if tun_interfaces:
            evidence.append("TUN/VPN " + ", ".join(tun_interfaces))
        process_text = ", ".join(process_names)
        process_note = (
            translate(language, "匹配进程 {processes}", processes=process_text)
            if process_text
            else translate(language, "未匹配到已配置进程名")
        )

        if active is True:
            reason = translate(
                language,
                "代理已启用：{evidence}；{process_note}",
                evidence="; ".join(evidence),
                process_note=process_note,
            )
        elif active is None:
            reason = translate(
                language,
                "无法确认代理是否启用（{errors}）",
                errors="; ".join(errors),
            )
            if process_text:
                reason += "; " + translate(language, "匹配进程 {processes}", processes=process_text)
        else:
            details: list[str] = [translate(language, "系统代理和 TUN/VPN 均未启用")]
            if configured_system:
                details.append(
                    translate(
                        language,
                        "系统代理端点不可连接 {endpoints}",
                        endpoints=", ".join(configured_system),
                    )
                )
            if process_text:
                details.append(
                    translate(language, "工具进程仍在运行 {processes}", processes=process_text)
                )
            if owned_endpoints:
                details.append(
                    translate(
                        language,
                        "仅发现监听端口 {endpoints}",
                        endpoints=", ".join(owned_endpoints),
                    )
                )
            reason = translate(language, "代理未启用：{details}", details="; ".join(details))

        return ClashStatus(
            active=active,
            running_processes=process_names,
            proxy_endpoints=tuple(sorted(reachable_system)),
            tun_interfaces=tuple(sorted(tun_interfaces)),
            reason=reason,
            listening_endpoints=tuple(sorted(owned_endpoints)),
        )

    @staticmethod
    def _find_processes(process_names: Iterable[str]) -> tuple[tuple[int, str], ...]:
        wanted = {str(name).strip().lower() for name in process_names}
        matches: list[tuple[int, str]] = []
        for process in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = str(process.info.get("name") or "").strip()
                executable = process.info.get("exe")
                candidates = {name.lower()}
                if executable:
                    candidates.add(Path(str(executable)).name.lower())
                if wanted.intersection(candidates):
                    matches.append((process.pid, name or Path(str(executable)).name))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return tuple(matches)

    @staticmethod
    def _find_owned_listeners(pids: set[int], ports: Iterable[int]) -> tuple[str, ...]:
        wanted_ports = set(ports)
        endpoints: set[str] = set()
        for connection in psutil.net_connections(kind="tcp"):
            if connection.pid not in pids or connection.status != psutil.CONN_LISTEN:
                continue
            address = connection.laddr
            if not address or int(address.port) not in wanted_ports:
                continue
            host = str(address.ip)
            if host in {"0.0.0.0", "::"}:
                host = "127.0.0.1"
            endpoints.add(f"{host}:{address.port}")
        return tuple(sorted(endpoints))

    @staticmethod
    def _system_proxy_endpoints() -> tuple[str, ...]:
        endpoints: set[str] = set()
        for scheme, raw_value in get_system_proxies().items():
            if scheme.lower() not in {"http", "https", "all", "socks"}:
                continue
            value = str(raw_value)
            parsed = urlparse(value if "://" in value else f"http://{value}")
            host = (parsed.hostname or "").lower()
            if not host or not parsed.port:
                continue
            endpoints.add(f"{host}:{parsed.port}")
        return tuple(sorted(endpoints))

    @staticmethod
    def _endpoint_reachable(endpoint: str) -> bool:
        host, port_text = endpoint.rsplit(":", 1)
        try:
            with socket.create_connection((host, int(port_text)), timeout=0.4):
                return True
        except OSError:
            return False

    @staticmethod
    def _active_tun_interfaces() -> tuple[str, ...]:
        interfaces: list[str] = []
        for name, stats in psutil.net_if_stats().items():
            lower_name = name.lower()
            if stats.isup and any(keyword in lower_name for keyword in CLASH_TUN_KEYWORDS):
                interfaces.append(name)
        return tuple(sorted(interfaces))


class ProcessTerminator:
    def terminate_named(self, process_names: Iterable[str], grace_seconds: float = 3.0) -> tuple[int, ...]:
        wanted = {name.lower() for name in process_names}
        current_pid = os.getpid()
        matched: list[psutil.Process] = []

        for process in psutil.process_iter(["pid", "name", "exe"]):
            try:
                if process.pid == current_pid:
                    continue
                candidates = {str(process.info.get("name") or "").lower()}
                executable = process.info.get("exe")
                if executable:
                    candidates.add(Path(str(executable)).name.lower())
                if wanted.intersection(candidates):
                    process.terminate()
                    matched.append(process)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
                LOG.warning("无法终止 PID %s: %s", getattr(process, "pid", "?"), exc)

        if not matched:
            return ()
        _, alive = psutil.wait_procs(matched, timeout=grace_seconds)
        for process in alive:
            try:
                process.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
                LOG.warning("无法强制终止 PID %s: %s", process.pid, exc)
        return tuple(process.pid for process in matched)


class GuardService:
    def __init__(
        self,
        config_path: Path,
        lookup: Optional[GeoLookup] = None,
        terminator: Optional[ProcessTerminator] = None,
        clash_detector: Optional[ClashDetector] = None,
        on_result: Optional[Callable[[CheckResult], None]] = None,
    ) -> None:
        self.config_path = config_path
        self.lookup = lookup or GeoLookup()
        self.terminator = terminator or ProcessTerminator()
        self.clash_detector = clash_detector or ClashDetector()
        self.on_result = on_result
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self.config = load_config(config_path)
        self._config_mtime_ns = self._get_config_mtime_ns()
        self.last_result = CheckResult(None, translate(self.config.language, "尚未检查"))

    def _get_config_mtime_ns(self) -> int:
        try:
            return self.config_path.stat().st_mtime_ns
        except OSError:
            return -1

    def reload_config(self) -> GuardConfig:
        config = load_config(self.config_path)
        with self._lock:
            self.config = config
            self._config_mtime_ns = self._get_config_mtime_ns()
            self._wake_event.set()
            return self.config

    def reload_if_changed(self) -> bool:
        mtime = self._get_config_mtime_ns()
        if mtime == self._config_mtime_ns:
            return False
        self.reload_config()
        self._publish(
            CheckResult(
                None,
                translate(self.config.language, "检测到配置变化，已自动重新加载"),
            )
        )
        return True

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self.config.enabled = bool(enabled)
            save_config(self.config_path, self.config)
            self._config_mtime_ns = self._get_config_mtime_ns()
            self._wake_event.set()
        self._publish(
            CheckResult(
                None,
                translate(
                    self.config.language,
                    "监控已开启" if enabled else "监控已暂停",
                ),
            )
        )

    def check_once(self, enforce: bool = True, force_refresh: bool = False) -> CheckResult:
        with self._lock:
            config = GuardConfig(**asdict(self.config)).normalized()

        clash_status = self.clash_detector.detect(config)
        configured_network_mode = config.ip_query_network_mode
        effective_network_mode = resolve_ip_query_network_mode(config, clash_status)
        config.ip_query_network_mode = effective_network_mode
        infos: tuple[IpInfo, ...] = ()
        evaluated: list[tuple[IpInfo, PolicyResult]] = []
        lookup_error: Exception | None = None
        try:
            lookup_all = getattr(self.lookup, "lookup_all", None)
            infos = (
                tuple(lookup_all(config, force_refresh=force_refresh))
                if lookup_all
                else (self.lookup.lookup(config),)
            )
            evaluated = [(info, evaluate_policy(info, config)) for info in infos]
        except Exception as exc:  # Keep the monitor alive when a provider is unavailable.
            lookup_error = exc
            LOG.exception("检查公网 IP 失败")

        denied = [(info, policy) for info, policy in evaluated if not policy.compliant]
        clash_denied = config.clash_required and clash_status.active is False
        clash_unknown = config.clash_required and clash_status.active is None
        if denied or clash_denied:
            compliant: Optional[bool] = False
        elif lookup_error is not None or clash_unknown:
            compliant = None
        else:
            compliant = True

        killed: tuple[int, ...] = ()
        should_terminate = compliant is False or (compliant is None and config.fail_closed)
        if should_terminate and enforce:
            killed = self.terminator.terminate_named(config.process_names)

        language = config.language
        if configured_network_mode == "auto":
            route_text = translate(
                language,
                "系统代理出口" if effective_network_mode == "system_proxy" else "本机直连",
            )
            network_reason = translate(language, "IP 检测线路：自动选择 {route}", route=route_text)
        else:
            network_reason = translate(
                language,
                "IP 检测线路：手动本机直连"
                if effective_network_mode == "direct"
                else "IP 检测线路：手动系统代理出口",
            )
        parts = [clash_status.reason, network_reason]
        primary: IpInfo | None = None
        if evaluated:
            observations = ", ".join(
                f"{info.country_code or '?'}@{info.ip}" for info, _ in evaluated
            )
            parts.append(translate(language, "多源观测 [{observations}]", observations=observations))
            if denied:
                parts.extend(policy.reason for _, policy in denied)
                primary = denied[0][0]
            else:
                parts.append(translate(language, "所有已观测出口均符合 IP 策略"))
                primary = infos[0]
        if lookup_error is not None:
            parts.append(translate(language, "IP 查询失败: {error}", error=lookup_error))
        if compliant is False:
            parts.append(
                translate(language, "已终止 {count} 个 Kiro 进程", count=len(killed))
                if enforce
                else translate(language, "未执行终止")
            )
        elif compliant is None:
            if config.fail_closed and enforce:
                parts.append(
                    translate(
                        language,
                        "故障关闭策略已终止 {count} 个 Kiro 进程",
                        count=len(killed),
                    )
                )
            else:
                parts.append(translate(language, "状态无法确认，未终止进程"))
        else:
            parts.append(translate(language, "代理状态与公网 IP 联合检查通过"))
        separator = "; " if effective_language(language) == "en" else "；"
        result = CheckResult(compliant, separator.join(parts), primary, killed, clash_status)
        self._publish(result)
        return result

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="ip-guard-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        next_check = 0.0
        while not self._stop_event.is_set():
            try:
                if self.reload_if_changed():
                    next_check = 0.0
            except ValueError as exc:
                LOG.error("配置自动重新加载失败: %s", exc)

            with self._lock:
                enabled = self.config.enabled
                interval = self.config.check_interval_seconds
            now = time.monotonic()
            if enabled and now >= next_check:
                self.check_once(enforce=True)
                next_check = time.monotonic() + interval
            elif not enabled:
                next_check = 0.0

            if enabled:
                wait_seconds = max(0.1, min(2.0, next_check - time.monotonic()))
            else:
                wait_seconds = 2.0
            woke = self._wake_event.wait(wait_seconds)
            self._wake_event.clear()
            if woke:
                next_check = 0.0

    def _publish(self, result: CheckResult) -> None:
        self.last_result = result
        if result.compliant is False:
            LOG.error(result.message)
        else:
            LOG.info(result.message)
        if self.on_result:
            try:
                self.on_result(result)
            except Exception:
                LOG.exception("状态回调执行失败")
