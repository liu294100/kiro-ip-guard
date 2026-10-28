from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

GITHUB_REPOSITORY = "liu294100/kiro-ip-guard"
GITHUB_LATEST_RELEASE_URL = f"https://github.com/{GITHUB_REPOSITORY}/releases/latest"
_VERSION_PATTERN = re.compile(r"^v?(\d+(?:\.\d+)*)$")


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    html_url: str


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


def check_latest_release(current_version: str, timeout: int = 8) -> ReleaseInfo | None:
    """Resolve GitHub's latest stable Release redirect without API rate-limit usage."""
    request = urllib.request.Request(
        GITHUB_LATEST_RELEASE_URL,
        headers={"User-Agent": f"Kiro-IP-Guard/{current_version}"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
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
    return ReleaseInfo(tag.removeprefix("v"), html_url)
