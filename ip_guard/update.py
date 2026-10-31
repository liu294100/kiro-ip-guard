from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, unquote, urlparse

import certifi

LOG = logging.getLogger("kiro_ip_guard")

GITHUB_REPOSITORY = "liu294100/kiro-ip-guard"
GITHUB_LATEST_RELEASE_URL = f"https://github.com/{GITHUB_REPOSITORY}/releases/latest"
GITHUB_DOWNLOAD_URL = f"https://github.com/{GITHUB_REPOSITORY}/releases/download"
CHECKSUM_ASSET = "SHA256SUMS"
MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024
_VERSION_PATTERN = re.compile(r"^v?(\d+(?:\.\d+)*)$")
_OLD_SUFFIX = ".old"
_NEW_SUFFIX = ".new"


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    html_url: str
    tag: str = ""


def _version_parts(value: str) -> tuple[int, ...]:
    match = _VERSION_PATTERN.fullmatch(value.strip())
    if not match:
        raise ValueError(f"Unsupported release version: {value}")
    parts = tuple(int(part) for part in match.group(1).split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def is_newer_version(candidate: str, current: str) -> bool:
    candidate_parts = _version_parts(candidate)
    current_parts = _version_parts(current)
    width = max(len(candidate_parts), len(current_parts))
    return candidate_parts + (0,) * (width - len(candidate_parts)) > current_parts + (0,) * (
        width - len(current_parts)
    )


def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where())


def check_latest_release(current_version: str, timeout: int = 8) -> ReleaseInfo | None:
    """Resolve GitHub's latest stable Release redirect without API rate-limit usage."""
    request = urllib.request.Request(
        GITHUB_LATEST_RELEASE_URL,
        headers={"User-Agent": f"Kiro-IP-Guard/{current_version}"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context()) as response:
            html_url = response.geturl()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RuntimeError(str(exc)) from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(str(exc)) from exc

    parsed = urlparse(html_url)
    releases_path = f"/{GITHUB_REPOSITORY}/releases"
    tag_prefix = releases_path + "/tag/"
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RuntimeError("GitHub returned an unexpected release URL")
    if parsed.path.rstrip("/") == releases_path:
        return None
    if not parsed.path.startswith(tag_prefix):
        raise RuntimeError("GitHub returned an unexpected release URL")
    tag = unquote(parsed.path[len(tag_prefix) :]).strip("/")
    if not is_newer_version(tag, current_version):
        return None
    return ReleaseInfo(tag.removeprefix("v"), html_url, tag)


# ---------------------------------------------------------------------------
# Self-update for packaged builds
# ---------------------------------------------------------------------------


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _current_target() -> Optional[Path]:
    """Return the file or bundle that an update replaces, or None if unsupported."""
    if not _is_frozen():
        return None
    executable = Path(sys.executable).resolve()
    system = platform.system()
    if system == "Windows":
        return executable
    if system == "Darwin":
        # .../KiroIPGuard.app/Contents/MacOS/KiroIPGuard
        bundle = executable.parents[2] if len(executable.parents) >= 3 else None
        if bundle is not None and bundle.suffix == ".app":
            return bundle
    return None


def release_asset_name(version: str, system: str | None = None, machine: str | None = None) -> str | None:
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    if machine in {"amd64", "x86_64", "x64"}:
        arch = "x64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        return None
    if system == "Windows":
        return f"KiroIPGuard-Windows-{arch}-onefile-v{version}.zip"
    if system == "Darwin":
        return f"KiroIPGuard-macOS-{arch}-onefile-v{version}.zip"
    return None


def can_self_update() -> bool:
    """True when running a packaged build in a location this user can write to."""
    target = _current_target()
    if target is None:
        return False
    if "AppTranslocation" in str(target):
        # macOS runs quarantined apps from a read-only random path.
        return False
    return os.access(target.parent, os.W_OK)


def _download(url: str, destination: Path, user_agent: str, timeout: int) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context()) as response:
            if urlparse(response.geturl()).scheme != "https":
                raise RuntimeError("Download was redirected to a non-HTTPS URL")
            declared = int(response.headers.get("Content-Length") or 0)
            if declared > MAX_DOWNLOAD_BYTES:
                raise RuntimeError("Release asset is too large")
            received = 0
            with destination.open("wb") as stream:
                while True:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAX_DOWNLOAD_BYTES:
                        raise RuntimeError("Release asset is too large")
                    stream.write(chunk)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{url}: HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"{url}: {exc}") from exc


def _expected_sha256(checksums: str, asset: str) -> str:
    for line in checksums.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].lstrip("*") == asset:
            digest = parts[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    raise RuntimeError(f"{CHECKSUM_ASSET} has no entry for {asset}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def _swap_into_place(target: Path, staged: Path) -> None:
    """Replace target with staged. A running executable can be renamed but not overwritten."""
    backup = target.with_name(target.name + _OLD_SUFFIX)
    if backup.exists():
        _remove_path(backup)
    os.replace(target, backup)
    try:
        os.replace(staged, target)
    except OSError:
        os.replace(backup, target)
        raise


def _extract_windows(archive: Path, target: Path) -> Path:
    staged = target.with_name(target.name + _NEW_SUFFIX)
    with zipfile.ZipFile(archive) as bundle:
        members = [
            info
            for info in bundle.infolist()
            if not info.is_dir() and Path(info.filename.replace("\\", "/")).name.lower() == "kiroipguard.exe"
        ]
        if not members:
            raise RuntimeError("KiroIPGuard.exe was not found in the release archive")
        if staged.exists():
            _remove_path(staged)
        with bundle.open(members[0]) as source, staged.open("wb") as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
    return staged


def _extract_macos(archive: Path, target: Path, work_dir: Path) -> Path:
    extract_dir = work_dir / "extracted"
    extract_dir.mkdir()
    # ditto keeps symlinks, permissions and code signatures inside the bundle.
    subprocess.run(["/usr/bin/ditto", "-x", "-k", str(archive), str(extract_dir)], check=True)
    candidates = sorted(
        path for path in extract_dir.rglob("*.app") if path.is_dir() and path.name == target.name
    )
    if not candidates:
        raise RuntimeError(f"{target.name} was not found in the release archive")
    staged = target.with_name(target.name + _NEW_SUFFIX)
    if staged.exists():
        _remove_path(staged)
    shutil.move(str(candidates[0]), str(staged))
    subprocess.run(
        ["/usr/bin/xattr", "-dr", "com.apple.quarantine", str(staged)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return staged


def install_release(
    release: ReleaseInfo,
    current_version: str,
    progress: Callable[[str], None] | None = None,
    timeout: int = 60,
) -> Path:
    """Download, verify and install a release over the running packaged build.

    Returns the installed executable or app bundle. The caller must restart.
    """
    target = _current_target()
    if target is None or not can_self_update():
        raise RuntimeError("Automatic installation is only available for writable packaged builds")
    asset = release_asset_name(release.version)
    if asset is None:
        raise RuntimeError(f"No release package for {platform.system()} {platform.machine()}")
    tag = release.tag or f"v{release.version}"
    base_url = f"{GITHUB_DOWNLOAD_URL}/{quote(tag)}"
    user_agent = f"Kiro-IP-Guard/{current_version}"
    report = progress or (lambda _message: None)

    with tempfile.TemporaryDirectory(prefix="kiro-ip-guard-update-") as temporary:
        work_dir = Path(temporary)
        checksums_path = work_dir / CHECKSUM_ASSET
        archive_path = work_dir / asset
        report("download")
        _download(f"{base_url}/{CHECKSUM_ASSET}", checksums_path, user_agent, timeout)
        expected = _expected_sha256(checksums_path.read_text(encoding="utf-8", errors="replace"), asset)
        _download(f"{base_url}/{quote(asset)}", archive_path, user_agent, timeout)
        report("verify")
        actual = _sha256(archive_path)
        if actual != expected:
            raise RuntimeError(f"SHA-256 mismatch for {asset}")
        report("install")
        if platform.system() == "Windows":
            staged = _extract_windows(archive_path, target)
        else:
            staged = _extract_macos(archive_path, target, work_dir)
        try:
            _swap_into_place(target, staged)
        except OSError:
            _remove_path(staged)
            raise
    LOG.info("Installed update v%s to %s", release.version, target)
    return target


def launch_installed(target: Path, arguments: list[str] | None = None) -> None:
    """Start the newly installed build as an independent process."""
    args = list(sys.argv[1:] if arguments is None else arguments)
    if platform.system() == "Windows":
        env = dict(os.environ)
        # Tell the PyInstaller bootloader that this is a new application
        # instance rather than a child of the current onefile process.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        subprocess.Popen(
            [str(target), *args],
            cwd=str(target.parent),
            env=env,
            creationflags=flags,
            close_fds=True,
        )
        return
    command = ["/usr/bin/open", "-n", str(target)]
    if args:
        command += ["--args", *args]
    subprocess.Popen(command, close_fds=True)


def cleanup_previous_install(wait_seconds: float = 60.0) -> None:
    """Remove the backup left by the previous update once its process has exited."""
    target = _current_target()
    if target is None:
        return
    leftovers = [
        target.with_name(target.name + _OLD_SUFFIX),
        target.with_name(target.name + _NEW_SUFFIX),
    ]
    deadline = time.monotonic() + wait_seconds
    while True:
        remaining = []
        for path in leftovers:
            if not (path.exists() or path.is_symlink()):
                continue
            try:
                _remove_path(path)
            except OSError:
                remaining.append(path)
        if not remaining or time.monotonic() >= deadline:
            for path in remaining:
                LOG.info("Could not remove previous update file yet: %s", path)
            return
        leftovers = remaining
        time.sleep(2)
