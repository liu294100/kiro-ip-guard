param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($Version)) {
    $VersionSource = Get-Content (Join-Path $Root "ip_guard\__init__.py") -Raw
    $VersionMatch = [regex]::Match($VersionSource, '(?m)^__version__\s*=\s*"([^"]+)"')
    if (-not $VersionMatch.Success) {
        throw "Unable to read __version__ from ip_guard\__init__.py"
    }
    $Version = $VersionMatch.Groups[1].Value
}
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') {
    throw "Invalid release version: $Version"
}

$Release = Join-Path $Root "release"
$OneFile = Join-Path $Release "KiroIPGuard-Windows-x64-onefile-v$Version"

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,
        [int]$Attempts = 6
    )

    for ($Attempt = 1; $Attempt -le $Attempts; $Attempt++) {
        try {
            & $Action
            return
        }
        catch {
            if ($Attempt -eq $Attempts) {
                throw "$Description failed after $Attempts attempts: $($_.Exception.Message)"
            }
            Write-Warning "$Description failed (attempt $Attempt/$Attempts); retrying in 2 seconds."
            Start-Sleep -Seconds 2
        }
    }
}

New-Item -ItemType Directory -Force $Release | Out-Null
if (Test-Path -LiteralPath $OneFile) {
    Invoke-WithRetry "Remove $OneFile" { Remove-Item -LiteralPath $OneFile -Recurse -Force -ErrorAction Stop }
}
New-Item -ItemType Directory -Force $OneFile | Out-Null

Invoke-WithRetry "Copy onefile executable" {
    Copy-Item (Join-Path $Root "dist\KiroIPGuard.exe") (Join-Path $OneFile "KiroIPGuard.exe") -Force -ErrorAction Stop
}

$Launchers = @{
    "Run.cmd" = "@echo off`r`nstart `"`" `"%~dp0KiroIPGuard.exe`"`r`n"
    "Settings.cmd" = "@echo off`r`nstart `"`" `"%~dp0KiroIPGuard.exe`" --settings`r`n"
    "Enable-Autostart.cmd" = "@echo off`r`n`"%~dp0KiroIPGuard.exe`" --install-autostart`r`necho Kiro IP Guard autostart enabled.`r`npause`r`n"
    "Disable-Autostart.cmd" = "@echo off`r`n`"%~dp0KiroIPGuard.exe`" --remove-autostart`r`necho Kiro IP Guard autostart disabled.`r`npause`r`n"
}

$Guide = @"
Kiro IP Guard v$Version

1. Run.cmd: start monitoring in the system tray.
2. Settings.cmd: edit allowlist, blocklist, cache and check interval.
3. Enable-Autostart.cmd / Disable-Autostart.cmd: manage user logon startup.
4. Defaults: an enabled, reachable OS proxy or an active TUN/VPN route is required, together with a compliant public IP.
5. Running proxy-tool processes and listening ports are diagnostics only; they do not mean the proxy is enabled.
6. Auto mode uses an enabled system proxy; otherwise it uses direct access while TUN/VPN routing still applies.
7. Direct and system-proxy modes remain available as manual overrides.
8. Claude trace reports the local client's public egress IP, not a Claude server IP.
9. Common Clash/Mihomo, V2Ray/Xray, sing-box, Shadowsocks, Hiddify, NekoRay, WireGuard, WARP and Tailscale tools are recognized.

Config: %APPDATA%\KiroIPGuard\config.json
See README.md for English documentation or README_zh.md for Chinese documentation.
"@

foreach ($Item in $Launchers.GetEnumerator()) {
    Set-Content -LiteralPath (Join-Path $OneFile $Item.Key) -Value $Item.Value -Encoding ASCII -NoNewline
}
Set-Content -LiteralPath (Join-Path $OneFile "Quick-Start.txt") -Value $Guide -Encoding ASCII
Copy-Item (Join-Path $Root "README.md") $OneFile
Copy-Item (Join-Path $Root "README_zh.md") $OneFile
Copy-Item (Join-Path $Root "assets\kiro-ip-guard.png") $OneFile

$OneFileZip = "$OneFile.zip"
if (Test-Path -LiteralPath $OneFileZip) {
    Invoke-WithRetry "Remove $OneFileZip" { Remove-Item -LiteralPath $OneFileZip -Force -ErrorAction Stop }
}
Invoke-WithRetry "Create onefile ZIP" {
    Compress-Archive -Path (Join-Path $OneFile "*") -DestinationPath $OneFileZip -CompressionLevel Optimal -ErrorAction Stop
}

Write-Output "Created: $OneFileZip"
