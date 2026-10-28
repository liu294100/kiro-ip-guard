# Kiro IP Guard

[English](README.md) | [简体中文](README_zh.md)

Kiro IP Guard 是一个 Windows / macOS 托盘守卫程序。它检查系统代理、TUN/VPN 及常见代理工具状态，
并查询当前公网 IP 和国家/地区；只有代理有效且公网出口符合白名单、黑名单及 IP/CIDR 策略时才放行，
明确不合规时终止名称匹配的 Kiro 进程。

> [!IMPORTANT]
> Claude 可用地区可能变化。项目按照 2026-10-26 查询到的
> [Anthropic 官方支持地区页面](https://platform.claude.com/docs/zh-CN/api/supported-regions)设置初始参考值，
> 但不会自动同步政策；请根据最新服务条款维护配置。默认只允许 ISO 国家代码 `US`。

## 功能

- 默认要求检测到可连接的系统代理端点或活动 TUN/VPN；仅有工具进程和监听端口不代表代理已启用。
- 代理状态与公网 IP 策略采用 **AND 联合判断**：即使 IP 显示为美国，代理未启用也会判为不合规。
- 兼容 Clash/Mihomo、V2Ray/Xray、sing-box、Shadowsocks、Hiddify、NekoRay/NekoBox、Trojan、WireGuard、WARP、Tailscale 等常见工具；未知工具只要正确启用系统代理或 TUN/VPN 也可识别。
- 托盘菜单开启或暂停监控，无需一直显示窗口。
- 设置窗口、Windows 任务栏、EXE 文件和系统托盘使用统一的 K/盾牌应用图标。
- 托盘图标叠加绿色（合规）、红色（不合规）、黄色（未检查/查询失败）状态。
- 设置页支持纵向滚动并按屏幕尺寸自适应，低分辨率和高 DPI 下底部按钮保持可见。
- “检测结果”页逐条显示普通查询源、Claude 路径看到的**本机公网出口 IP**、国家、合规状态和检测时间。
- 默认使用“自动选择”模式：系统代理已实际启用时查询代理出口；否则走直连，活动 TUN/VPN 仍由系统路由接管。
- 仍可手动固定为“始终本机直连”或“系统代理出口”；系统代理模式每次请求都会重新读取代理配置。
- 默认每 1 秒重新执行一次策略检查和进程保护，周期可配置。
- 每次策略检查都重新查询当前公网出口 IP，切换网络/IP 后最迟一个检查周期内生效。
- 仅缓存“具体 IP → GeoIP/地区结果”600 秒，相同 IP 不重复查询地区服务。
- 支持国家/地区白名单、黑名单，以及精确 IP 或 CIDR 黑名单。
- Windows 和 macOS 均按**进程名精确匹配**终止 `kiro` / `kiro-cli`，不会按命令行模糊匹配。
- 并发查询多家来源：SKK IP API、ipwho.is、ipapi.co；单家失败不影响其他结果。
- 对每个成功观测的出口使用 Net.Coffee GeoIP API 补充国家/地区，补充失败时使用 IP 源自身结果。
- 只要任一成功观测的出口不合规就执行终止，可发现按域名分流产生的不同出口。
- 默认“查询失败不杀进程”，可切换为故障关闭模式。
- 支持中文、English 和跟随系统语言，设置保存后托盘与设置窗口自动采用所选语言。
- 启动时可自动检查 [GitHub Releases](https://github.com/liu294100/kiro-ip-guard/releases)，发现新版本后由用户打开下载页，不静默替换程序。
- 支持用户级开机自启，以及 PyInstaller `onefile` 打包。

## 安装

要求 Python 3.10 或更高版本。

### Windows

```powershell
cd D:\tmp\kiro-ip-guard
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m ip_guard
```

### macOS

```bash
cd /path/to/kiro-ip-guard
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m ip_guard
```

首次运行会自动创建配置。托盘图标中：绿色表示最近一次合规，红色表示不合规，黄色表示尚未检查或查询失败。
双击托盘图标或右键选择“打开设置…”即可进入图形配置窗口。

首次安装依赖后，也可以直接双击项目根目录的一键脚本：

- Windows：`启动监控.cmd`、`打开设置.cmd`、`开启开机启动.cmd`、`关闭开机启动.cmd`
- macOS：对应的 `*-macOS.command` 文件；首次使用前需要为这些文件和 `scripts/macos/*.sh` 添加执行权限

## 图形化设置

设置窗口分为“策略与监控”“启动与更新”“查询源”“检测结果”四个标签页，可修改：

- 在“启动与更新”中切换中文、English 或跟随系统语言，并启用/停用 GitHub Releases 自动检查。

- 开启/暂停后台监控、策略检查间隔、同一 IP 的地区缓存时间和网络超时。
- 在“仅白名单”“仅黑名单”“组合模式”之间切换。
- 国家/地区白名单及黑名单。
- IP/CIDR 黑名单和需要终止的进程名。
- 查询失败时是否故障关闭。
- 开启或关闭“要求系统代理或 TUN/VPN 已实际启用”；默认开启。
- 配置常见代理工具进程名和监听端口；这些字段用于辅助诊断，不单独作为代理启用依据。
- 查看、开启或关闭当前用户的开机启动。
- 在“查询源”页选择推荐的“自动选择”，或手动固定为“始终本机直连”“系统代理出口”。
- SKK、ipwho.is、ipapi.co、Net.Coffee 等查询源。
- 默认检测 `claude.ai` 和 `api.anthropic.com` 的实际访问路径，识别按域名分流。

点击“测试当前 IP（不终止进程）”会查询多家来源并显示判断结果，不会结束 Kiro。后台每个检查周期都会重新获取
当前出口 IP；托盘菜单的“立即检查（刷新地区缓存）”还会绕过该 IP 已有的地区缓存。点击“保存”后，后台托盘程序
会在约 2 秒内自动加载配置；不需要重启。

也可以不启动托盘，直接打开设置窗口：

```powershell
# Windows
.venv\Scripts\pythonw.exe -m ip_guard --settings
```

```bash
# macOS
.venv/bin/python -m ip_guard --settings
```

> [!NOTE]
> Tkinter 通常随 Windows 和 python.org 的 macOS Python 一起安装。如果 macOS 使用的 Python 未包含 Tk，
> 请先通过该 Python 发行版的包管理方式安装 Tk 支持。

## 配置

配置文件默认位置：

- Windows：`%APPDATA%\KiroIPGuard\config.json`
- macOS：`~/Library/Application Support/KiroIPGuard/config.json`

也可以用 `--config` 指定其他路径。推荐通过托盘的“打开设置…”修改；程序仍保留“打开配置目录”和
“重新加载配置”供高级用户使用。外部修改 JSON 后，后台也会在约 2 秒内自动重载。完整示例见
`config.example.json`。

| 配置项 | 默认值 | 说明 |
|:-------|:------:|:-----|
| `enabled` | `true` | 是否启动周期监控 |
| `policy_mode` | `combined` | `allowlist`、`blocklist` 或 `combined` |
| `config_version` | `2` | 配置格式版本；旧版默认 `direct` 会在首次加载时自动迁移为 `auto` |
| `ip_query_network_mode` | `auto` | `auto` 在系统代理启用时查代理出口，否则走直连/TUN 路由；另两项为手动固定模式 |
| `language` | `auto` | `zh-CN`、`en` 或 `auto`（跟随系统语言） |
| `check_updates` | `true` | 启动后及每 24 小时检查一次 GitHub Releases；失败不影响防护 |
| `check_interval_seconds` | `1` | 策略检查周期，最小 1 秒；每次都会重新判断是否合规 |
| `cache_ttl_seconds` | `600` | 同一 IP 对应的 GeoIP/地区缓存秒数；当前出口 IP 不缓存；`0` 禁用地区缓存 |
| `allowed_country_codes` | `["US"]` | ISO 3166-1 alpha-2 白名单；空数组表示不限制 |
| `blocked_country_codes` | `CN/CU/HK/IR/KP/MO/RU/SY` | 中国大陆、古巴、香港、伊朗、北韩、澳门、俄罗斯、叙利亚参考黑名单 |
| `blocked_ip_networks` | `[]` | IP/CIDR 黑名单，例如 `203.0.113.0/24` |
| `process_names` | Kiro 名称列表 | 要终止的进程名，精确匹配且不区分大小写 |
| `fail_closed` | `false` | `true` 时无法确认代理状态或所有 IP 查询源失败也终止 Kiro；启用前请评估误杀风险 |
| `clash_required` | `true` | 是否要求系统代理或 TUN/VPN 实际启用；字段名为兼容旧配置而保留 |
| `clash_process_names` | 常见代理工具名称 | 辅助显示运行中的工具；未知工具仍可通过系统代理/TUN 识别 |
| `clash_proxy_ports` | 常见 HTTP/SOCKS 端口 | 仅用于诊断匹配进程的监听端口，不作为代理已启用的依据 |
| `claude_route_checks_enabled` | `true` | 自动检测 Claude 与 Anthropic 域名的实际出口 |
| `providers` | SKK、ipwho.is、ipapi.co、Claude、Anthropic | 每次检查并发获取当前公网出口 IP |
| `geo_providers` | Net.Coffee | 为每个出口补充地区，URL 中用 `{ip}` 占位 |

默认黑名单使用 `CN`、`HK`、`MO`、`RU`、`IR`、`KP`、`SY`、`CU`。官方页面给出了支持列表而不是完整的
“受制裁地区黑名单”，因此程序没有猜测“其他地区”。如政策更新，请显式增删 ISO 代码。

三种策略模式：

- `allowlist`：只检查国家/地区白名单，忽略国家、IP 和 CIDR 黑名单字段。
- `blocklist`：只检查国家、IP 和 CIDR 黑名单，忽略白名单字段。
- `combined`：先检查黑名单，再检查白名单；这是默认模式。

多个查询域名可能因代理分流观察到不同出口；程序要求所有成功观测到的出口均合规。默认还要求
`clash_required=true`（字段名为兼容旧配置而保留）：必须检测到以下至少一种真实代理信号：可连接的 OS 系统代理端点，
或活动 TUN/VPN 网卡。匹配进程和监听端口只用于诊断，**不会再单独判定代理已启用**。因此客户端进程仍驻留、
但系统代理和 TUN 都已关闭时，会按未启用处理并自动查询直连出口。

每隔 `check_interval_seconds` 秒都会重新访问公网 IP 来源，**当前出口 IP 永不缓存**。获取当前 IP 后，再按 IP 地址读取
GeoIP/地区缓存；IP 发生变化时会立即为新 IP 查询地区，切回旧 IP 时才可能复用该旧 IP 自己的缓存。缓存时间由
`cache_ttl_seconds` 控制。IP 查询或代理状态无法确认时，才按 `fail_closed` 决定是否终止进程；明确检测到代理
未启用时属于不合规，不受 `fail_closed=false` 影响。

示例：只允许美国和加拿大，同时明确阻止一个网段：

```json
{
  "policy_mode": "combined",
  "allowed_country_codes": ["US", "CA"],
  "blocked_country_codes": [],
  "blocked_ip_networks": ["203.0.113.0/24"]
}
```

> [!CAUTION]
> `fail_closed=true` 会在断网、DNS 故障、查询服务限流或服务不可用时终止 Kiro。默认保持 `false` 更能避免误杀。

## 线路切换排查

1. 确认窗口标题为 **Kiro IP Guard v1.4.0**；先退出所有旧托盘实例，再启动新版本。
2. 打开“检测结果”标签，点击“检测当前出口（不终止进程）”，先查看顶部代理状态。
3. 开启系统代理时应显示可连接的代理端点；使用 TUN/VPN 时应显示活动网卡。工具进程和端口仅供诊断。
4. 再查看 `claude.ai`、`api.anthropic.com` 和普通查询域名看到的本机公网出口 IP。这些接口返回请求方 IP，
   不是查询网站或 Claude 服务器自身的 IP。
5. 如果客户端按钮已关闭但仍显示“系统代理”，请检查 Windows“设置 → 网络和 Internet → 代理”；程序读取的是操作系统真实代理状态。
6. 只有代理状态与 IP 策略均合规才会放行；如果线路出口不符合策略，仍会终止 Kiro。
7. 推荐选择“自动选择”：存在可连接的系统代理时使用 `system_proxy`；否则使用 `direct`。TUN/VPN 属于系统路由，
   因而在 `direct` 下仍会经过 TUN/VPN。可临时使用两个手动模式排障。

Windows 自动模式直接读取当前用户注册表的系统代理开关，不使用 `HTTP_PROXY`、`HTTPS_PROXY` 环境变量作为启用依据。
`direct` 模式通过 `ProxyHandler({})` 明确忽略环境变量和系统 HTTP(S) 代理；`system_proxy` 模式则在每次请求时
重新读取最新代理配置。这里的“本机公网 IP”指本机按所选网络模式访问对应域名时，对方看到的公网出口。

## 命令行检查

只检查并显示结果，不终止任何进程：

```powershell
.venv\Scripts\python -m ip_guard --check-only
```

检查一次并执行终止策略：

```powershell
.venv\Scripts\python -m ip_guard --once
```

退出码：`0` 合规、`2` 不合规、`3` 查询失败。

## 运行方式与开机自启

“开启后台监控”和“开启开机启动”是两个独立设置：

- **手动运行模式**：只在本次登录会话启动托盘，不写系统启动项。
- **开机启动模式**：用户登录后自动启动托盘；仍需保持配置中的“开启后台监控”已勾选。
- **暂停监控**：程序和托盘仍驻留，但不查询 IP，也不终止 Kiro。

最方便的方式是在 GUI 的“启动方式”标签页点击“开启开机启动”或“关闭开机启动”。也可以使用脚本：

| 操作 | Windows | macOS |
|:-----|:--------|:------|
| 手动后台运行 | `scripts\windows\start-manual.cmd` | `scripts/macos/start-manual.sh` |
| 打开图形设置 | `scripts\windows\open-settings.cmd` | `scripts/macos/open-settings.sh` |
| 开启开机启动 | `scripts\windows\install-autostart.cmd` | `scripts/macos/install-autostart.sh` |
| 关闭开机启动 | `scripts\windows\remove-autostart.cmd` | `scripts/macos/remove-autostart.sh` |
| 整理 Windows 发布 ZIP | `scripts\windows\package-release.ps1` | 在 macOS 构建后自行归档 `.app` |

macOS 首次使用脚本前执行：

```bash
chmod +x scripts/macos/*.sh
```

这些脚本按以下顺序自动选择运行目标：

1. 环境变量 `KIRO_IP_GUARD_EXE` 指定的可执行文件。
2. `dist` 中的 `onefile` 产物。
3. `dist` 中的 macOS `.app` 内部可执行文件。
4. 项目 `.venv` 中的 Python 源码模式。

因此打包后无需修改脚本。若可执行文件位于自定义目录，可以先设置环境变量：

```powershell
$env:KIRO_IP_GUARD_EXE = "C:\Tools\KiroIPGuard.exe"
scripts\windows\start-manual.cmd
```

```bash
export KIRO_IP_GUARD_EXE="/Applications/KiroIPGuard.app/Contents/MacOS/KiroIPGuard"
scripts/macos/start-manual.sh
```

也可以直接使用 CLI：

```powershell
.venv\Scripts\python -m ip_guard --install-autostart
.venv\Scripts\python -m ip_guard --remove-autostart
```

Windows 会写入当前用户 Startup 目录；macOS 会写入
`~/Library/LaunchAgents/com.local.kiro-ip-guard.plist`。自启项会记录当前源码环境或打包程序的绝对路径，移动程序后需重新安装。

## 打包为独立程序

在对应操作系统上，可直接使用项目根目录的一键 Release 脚本构建 `onefile`，再生成带版本号的 ZIP 到 `release/`；不传版本号时自动读取 `ip_guard/__init__.py` 中的 `__version__`：

```powershell
# Windows
release.bat
# 指定发布版本
release.bat 1.4.0
```

```bash
# macOS
chmod +x release.sh scripts/macos/*.sh
./release.sh
# 指定发布版本
./release.sh 1.4.0
```

Windows：

```powershell
scripts\windows\build.cmd
```

macOS 必须在 macOS 机器上构建：

```bash
chmod +x scripts/macos/*.sh
scripts/macos/build.sh
```

脚本会创建 `.venv`（若不存在）、安装 `requirements-build.txt` 中固定版本的依赖，并将产物写入 `dist`。
Windows 构建会把 `assets/kiro-ip-guard.ico` 嵌入 EXE，并打包运行时 PNG；macOS 构建使用 ICNS。
不同操作系统必须在对应系统上分别打包。建议先手动运行产物，确认托盘和设置窗口正常，再从该产物开启开机启动。

如果已经分别完成 Windows 的两种构建，也可以只整理可分发 ZIP：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\package-release.ps1
```

输出位于 `release/`。Windows 包包含 `Run.cmd`、`Settings.cmd`、`Enable-Autostart.cmd`、
`Disable-Autostart.cmd` 和使用说明；macOS 包包含 `.app`、使用说明和中英文 README。

### GitHub Actions 自动发布

`.github/workflows/ci.yml` 会在 push、pull request 和手动触发时，于 Windows 与 macOS 运行编译检查和单元测试。
`.github/workflows/release.yml` 会在推送版本标签时构建 Windows x64 与 macOS runner 对应架构的 onefile ZIP，生成
`SHA256SUMS` 并创建 GitHub Release。标签必须与 `ip_guard/__init__.py` 中的版本一致：

```powershell
git tag v1.4.0
git push origin v1.4.0
```

自动更新只读取官方仓库 `liu294100/kiro-ip-guard` 的最新稳定 Release。程序不会下载或执行未经用户确认的文件，
更新检查失败也不会参与 IP 合规判断。

## 权限与隐私

- 守卫通常只能终止同一用户拥有的进程。若 Kiro 以管理员/root 身份运行，守卫也需对应权限。
- Clash 状态检查只读取本机进程名、TCP 监听、系统代理和网卡状态，不读取 Clash 配置、节点或流量内容。
- 程序每个检查周期都会并发请求 SKK（`ip.api.skk.moe`）、ipwho.is、ipapi.co 获取当前出口，并把首次出现或地区缓存
  过期的 IP 发送给 Net.Coffee（`ip.net.coffee`）查询地区；这些第三方会看到请求来源和/或待查询 IP。
- 日志写在配置目录的 `kiro-ip-guard.log`，使用轮转方式，最多保留 3 个约 1 MB 的历史文件。
- 程序不会修改代理、VPN、网络路由或 Kiro 文件，只在不合规时终止匹配进程。

## 验证

```powershell
python -m compileall -q ip_guard tests run_guard.py
python -m unittest discover -s tests -v
```
