"""Local MaxMind-format (mmdb) country database with automatic updates.

The default data source is Loyalsoldier/geoip ``Country-without-asn.mmdb``
(GeoLite2-compatible schema, rebuilt every Thursday). Any GeoLite2/GeoIP2
Country compatible mmdb file, such as the ``Country.mmdb`` used by Clash or
mihomo, can be used through a custom path.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import maxminddb

LOG = logging.getLogger("kiro_ip_guard")

LOCAL_GEOIP_FILENAME = "Country-without-asn.mmdb"
LOCAL_GEOIP_URLS = (
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb",
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country-without-asn.mmdb",
)
# Upstream rebuilds weekly; refresh a managed copy once it is older than this.
LOCAL_GEOIP_MAX_AGE_SECONDS = 7 * 24 * 3600
# After a failed download, wait before trying again so a 1-second check loop
# does not hammer the mirrors while offline.
LOCAL_GEOIP_RETRY_SECONDS = 3600
LOCAL_GEOIP_DOWNLOAD_TIMEOUT = 120
_VALIDATION_IP = "8.8.8.8"


@dataclass(frozen=True)
class LocalGeoStatus:
    path: Path
    managed: bool
    available: bool
    build_epoch: int = 0
    updating: bool = False
    last_error: str = ""


def _country_from_record(record: object) -> tuple[str, str] | None:
    """Return (ISO code, English name) or None for non-country records."""
    if not isinstance(record, dict):
        return None
    country = record.get("country") or record.get("registered_country")
    code = ""
    name = ""
    if isinstance(country, dict):
        code = str(country.get("iso_code") or "")
        names = country.get("names")
        if isinstance(names, dict):
            name = str(names.get("en") or "")
    elif "country_code" in record:  # ip-location-db style flat records
        code = str(record.get("country_code") or "")
    code = code.strip().upper()
    # Special categories such as PRIVATE are not countries; let the caller
    # fall back to the online providers instead of guessing.
    if len(code) != 2 or not code.isalpha():
        return None
    return code, name


def _open_reader(path: Path) -> maxminddb.Reader:
    # MODE_MEMORY reads the whole file and closes it, so a later atomic
    # replace works on Windows while the old reader is still in use.
    return maxminddb.open_database(str(path), maxminddb.MODE_MEMORY)


def validate_database(path: Path) -> None:
    """Raise if the file is not a readable country-level mmdb."""
    reader = _open_reader(path)
    try:
        database_type = str(reader.metadata().database_type)
        if "country" not in database_type.lower():
            raise ValueError(f"不是国家/地区类型的 mmdb: {database_type}")
        if _country_from_record(reader.get(_VALIDATION_IP)) is None:
            raise ValueError(f"mmdb 无法解析 {_VALIDATION_IP} 的国家/地区")
    finally:
        reader.close()


class LocalGeoDatabase:
    def __init__(
        self,
        data_dir: Path,
        urls: tuple[str, ...] = LOCAL_GEOIP_URLS,
        proxies_provider: Optional[Callable[[], dict[str, str]]] = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.urls = urls
        self.proxies_provider = proxies_provider or (lambda: {})
        self._lock = threading.RLock()
        self._update_lock = threading.Lock()
        self._reader: maxminddb.Reader | None = None
        self._reader_key: tuple[str, int, int] | None = None
        self._failed_key: tuple[str, int, int] | None = None
        self._updating = False
        self._next_attempt = 0.0
        self._last_error = ""

    @property
    def managed_path(self) -> Path:
        return self.data_dir / LOCAL_GEOIP_FILENAME

    def resolve_path(self, custom_path: str = "") -> Path:
        custom = str(custom_path or "").strip()
        return Path(os.path.expandvars(os.path.expanduser(custom))) if custom else self.managed_path

    def lookup(self, ip: str, custom_path: str = "") -> tuple[str, str, Path] | None:
        """Look up a country locally. Returns None when no usable record exists."""
        path = self.resolve_path(custom_path)
        managed = not str(custom_path or "").strip()
        if managed:
            self._schedule_update_if_needed(path)
        reader = self._get_reader(path)
        if reader is None:
            return None
        try:
            with self._lock:
                record = reader.get(ip)
        except (ValueError, maxminddb.InvalidDatabaseError) as exc:
            LOG.warning("本地 GeoIP 查询失败 %s: %s", ip, exc)
            return None
        country = _country_from_record(record)
        if country is None:
            return None
        return country[0], country[1], path

    def status(self, custom_path: str = "") -> LocalGeoStatus:
        path = self.resolve_path(custom_path)
        reader = self._get_reader(path)
        build_epoch = 0
        if reader is not None:
            with self._lock:
                build_epoch = int(reader.metadata().build_epoch)
        return LocalGeoStatus(
            path=path,
            managed=not str(custom_path or "").strip(),
            available=reader is not None,
            build_epoch=build_epoch,
            updating=self._updating,
            last_error=self._last_error,
        )

    def update(self) -> Path:
        """Download, verify, and atomically install the managed database."""
        with self._update_lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            destination = self.managed_path
            temporary = destination.with_name(destination.name + ".download")
            errors: list[str] = []
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler(self.proxies_provider())
            )
            for url in self.urls:
                try:
                    self._download(opener, url, temporary)
                    validate_database(temporary)
                    os.replace(temporary, destination)
                    self._last_error = ""
                    LOG.info("本地 GeoIP 数据库已更新: %s (来源 %s)", destination, url)
                    return destination
                except Exception as exc:  # Try the next mirror.
                    errors.append(f"{url}: {exc}")
                    LOG.warning("本地 GeoIP 数据库下载失败 %s: %s", url, exc)
                finally:
                    temporary.unlink(missing_ok=True)
            self._last_error = "; ".join(errors)
            raise RuntimeError("本地 GeoIP 数据库下载失败: " + self._last_error)

    @staticmethod
    def _download(opener: urllib.request.OpenerDirector, url: str, target: Path) -> None:
        headers = {"User-Agent": "KiroIPGuard", "Cache-Control": "no-cache"}
        digest = hashlib.sha256()
        request = urllib.request.Request(url, headers=headers)
        with opener.open(request, timeout=LOCAL_GEOIP_DOWNLOAD_TIMEOUT) as response, target.open("wb") as file:
            while chunk := response.read(256 * 1024):
                digest.update(chunk)
                file.write(chunk)
        expected = ""
        try:
            checksum_request = urllib.request.Request(url + ".sha256sum", headers=headers)
            with opener.open(checksum_request, timeout=30) as response:
                expected = response.read(4096).decode("ascii", errors="replace").split()[0].lower()
        except Exception as exc:
            # The mmdb structure is still validated before installation.
            LOG.warning("无法获取 GeoIP 校验文件 %s.sha256sum: %s", url, exc)
        if expected and expected != digest.hexdigest():
            raise ValueError("SHA-256 校验失败")

    def _schedule_update_if_needed(self, path: Path) -> None:
        try:
            age = time.time() - path.stat().st_mtime
        except OSError:
            age = float("inf")
        if age < LOCAL_GEOIP_MAX_AGE_SECONDS:
            return
        now = time.monotonic()
        with self._lock:
            if self._updating or now < self._next_attempt:
                return
            self._updating = True
            self._next_attempt = now + LOCAL_GEOIP_RETRY_SECONDS

        def worker() -> None:
            try:
                self.update()
            except Exception:
                pass  # Already logged; the caller keeps using the old file or the online API.
            finally:
                self._updating = False

        threading.Thread(target=worker, name="geoip-db-update", daemon=True).start()

    def _get_reader(self, path: Path) -> maxminddb.Reader | None:
        try:
            stat = path.stat()
        except OSError:
            return None
        key = (str(path), stat.st_mtime_ns, stat.st_size)
        with self._lock:
            if self._reader is not None and self._reader_key == key:
                return self._reader
            if self._failed_key == key:
                return None
            try:
                reader = _open_reader(path)
            except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
                # Remember the broken file so the 1-second loop logs it once.
                self._failed_key = key
                LOG.warning("无法打开本地 GeoIP 数据库 %s: %s", path, exc)
                return None
            if self._reader is not None:
                self._reader.close()
            self._reader = reader
            self._reader_key = key
            return reader
