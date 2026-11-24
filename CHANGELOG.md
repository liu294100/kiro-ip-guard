# Changelog
## Unreleased
### Local GeoIP database first
- New setting `geo_lookup_mode` (Settings → Providers → Region lookup). The default is `local`: the region of each egress IP is read from a local mmdb file, and the online GeoIP providers are called only when the file is missing or has no record. `api` keeps the previous online-only behavior.
- The default database is `Country-without-asn.mmdb` from [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip). It is downloaded in the background to the configuration folder on first use, verified with its SHA-256 file, and refreshed every 7 days. Failed downloads are retried after 1 hour; until then the online providers are used.
- `geoip_db_path` can point at any GeoLite2/GeoIP2 Country compatible file, such as the `Country.mmdb` from Clash or mihomo. Custom files are never downloaded or overwritten.
- The Providers tab is now scrollable and shows the database status, with **Choose file...**, **Restore default location**, and **Update local database** buttons. A custom path is checked when saving and must point at an existing file.
- The Results tab shows the region reported by each IP provider and the GeoIP region side by side, plus where the GeoIP region came from (local database or online API). A summary line shows the lookup mode and database status, and IPs whose two regions differ are listed after a test.
### STUN egress check
- New STUN (RFC 5389) client with no extra dependencies. The route is chosen automatically: when a system proxy is active, requests go through the proxy's SOCKS5 UDP relay (Clash/mihomo mixed ports support this); otherwise they are sent as plain UDP, and TUN rules still apply. The SOCKS5 port is chosen the same way the HTTPS checks detect proxies. The app tries the system proxy port first, then the ports on the common-port list (`clash_proxy_ports`) that detected proxy tools are listening on. It uses the first port that accepts SOCKS5 UDP and remembers it for the next check. So v2rayN works even when its system proxy points at the HTTP-only port 10809. `stun_socks_proxy` sets a port manually.
- Default server: `stun.cloudflare.com:3478`. Add more in `stun_servers` and choose any number of them as active (`stun_active_servers`). Settings → Providers shows a selectable list.
- `stun_enabled` is off by default. When on, every active STUN egress must pass the IP policy as well. If all STUN servers fail, the status is unknown and `fail_closed` decides.
- The Results tab has a new **Method** column (HTTPS direct, HTTPS system proxy, STUN UDP direct, or STUN via SOCKS5). It always shows the STUN rows, marked display only while STUN is off, and failed servers with their error.
- Fixed: the region from `ip.api.skk.moe` could be read from its coordinate field `loc`. Only two-letter ISO codes are accepted now.
- New dependency: `maxminddb`.

## v1.6.0

### Automatic log cleanup

- Logs are now written to one file per day, for example `kiro-ip-guard-2026-10-31.log`. Files are never renamed, so the tray and settings processes can write to them at the same time without the Windows rollover errors that previously stopped old logs from being removed.
- A daily file that reaches 5 MB continues in `-1.log`, `-2.log`, and so on.
- Logs older than 7 days are deleted automatically. When all logs together exceed 30 MB, the oldest files are deleted first.
- Cleanup runs at startup, when the date changes, and every 10 minutes.
- Old `kiro-ip-guard.log` and `.log.1`–`.log.3` files from earlier versions are removed automatically.
- A check result is logged only when it changes. An unchanged result is repeated once every 10 minutes to show the guard is still running. This removes most of the log volume caused by the default 1-second check interval.
- Logs stay in the configuration folder.

### One-click and automatic updates

- When a new version is found, the tray menu shows **Install update vX (restarts automatically)**. The app:
  1. Downloads the package for your platform and the `SHA256SUMS` file from the GitHub Release.
  2. Verifies the SHA-256 checksum and stops if it does not match.
  3. Replaces the running build. On Windows, the running `KiroIPGuard.exe` is renamed to `.exe.old` and the new executable is put in its place. On macOS, the package is extracted with `ditto` so signatures and permissions are kept, and the `.app` bundle is replaced the same way.
  4. Starts the new version with the same arguments and exits. The new version removes the `.old` backup after the previous process has exited.
- If installation fails, the original files are restored and a notification links you to the manual download.
- New option in **Settings → Startup & Updates**: **Automatically download, verify, install and restart when an update is found**. It is on by default, so the background check (at startup and every 2 hours) installs new versions without asking. Turn it off to be notified and install from the tray menu instead.
- **Check for updates** in the settings window points you to the tray menu, because the tray process owns the running executable and performs the replacement.
- Automatic installation is not available when running from source, when the app folder is not writable (such as `Program Files`), when macOS runs the app from a temporary read-only location, or when no package exists for your platform (macOS packages are currently built for Apple Silicon only). In these cases the tray menu opens the download page instead.

### Build

- The macOS release package is now built on the `macos-26` runner because GitHub is retiring `macos-14`.

### Upgrade note

Self-update starts working from this version. Users on v1.5.2 or earlier need to install v1.6.0 manually once; later updates can then be installed with one click or automatically.
