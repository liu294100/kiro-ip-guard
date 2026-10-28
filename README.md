# Kiro IP Guard

[English](README.md) | [简体中文](README_zh.md)

Kiro IP Guard is a Windows and macOS tray application that requires an active system proxy or TUN/VPN and checks the current public egress IP against allowlists, blocklists, and IP/CIDR rules. When the result is explicitly non-compliant, it terminates matching Kiro processes.

## Highlights

- Exact process-name matching for `kiro` and `kiro-cli` on Windows and macOS.
- Combined system proxy/TUN/VPN and public-IP policy checks.
- Concurrent public IP queries with per-IP GeoIP caching.
- Chinese, English, and system-language UI modes.
- User-level login startup.
- Optional GitHub Releases checks at startup and every 2 hours.
- PyInstaller onefile packages.
- GitHub Actions CI and tag-based GitHub Releases.

## Install from source

Python 3.10 or newer is required.

```powershell
# Windows
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m ip_guard
```

```bash
# macOS
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m ip_guard
```

Open the tray menu and select **Open settings…**. The default configuration is stored at `%APPDATA%\KiroIPGuard\config.json` on Windows and `~/Library/Application Support/KiroIPGuard/config.json` on macOS.

## Defaults

- Policy mode: combined.
- Allowed countries/regions: `US`.
- Blocked countries/regions: `CN`, `CU`, `HK`, `IR`, `KP`, `MO`, `RU`, `SY`.
- Check interval: 1 second.
- GeoIP cache: 600 seconds.
- Language: system default; select Chinese or English under **Startup & Updates**.
- Update checks: enabled. Checks use the latest stable release from [liu294100/kiro-ip-guard](https://github.com/liu294100/kiro-ip-guard/releases).

Update checks only notify the user and open the official GitHub Release page after confirmation. The app does not silently replace or execute downloaded files. Update failures do not affect IP policy enforcement.

## Command line

```powershell
# Check without terminating processes
.venv\Scripts\python -m ip_guard --check-only

# Check once and enforce the policy
.venv\Scripts\python -m ip_guard --once

# Open settings
.venv\Scripts\pythonw.exe -m ip_guard --settings
```

Exit codes are `0` for compliant, `2` for non-compliant, and `3` when the result cannot be determined.

## Build packages

```powershell
# Windows onefile ZIP
release.bat
```

```bash
# macOS onefile ZIP
chmod +x release.sh scripts/macos/*.sh
./release.sh
```

## GitHub Actions release

`.github/workflows/ci.yml` runs compilation and unit tests on Windows and macOS. `.github/workflows/release.yml` builds onefile packages, generates `SHA256SUMS`, and creates a GitHub Release when a `v*` tag is pushed. The tag must match `ip_guard.__version__` exactly.

```bash
git tag v1.4.0
git push origin v1.4.0
```

## Privacy and permissions

The app reads local process names, TCP listeners, system proxy settings, and network-interface state. It sends public-IP requests to the configured providers and sends an IP to configured GeoIP providers when its region cache is missing or expired. Logs are stored beside the configuration file. The app does not modify proxy, VPN, routing, or Kiro files.

## Verify

```powershell
python -m compileall -q ip_guard tests run_guard.py
python -m unittest discover -s tests -v
```
