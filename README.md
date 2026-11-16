# cf-tunnel-panel

用 Cloudflare Tunnel 把本机服务暴露到公网——Windows 托盘版与 Linux 服务端，共用同一套 Web UI。

同一份核心逻辑（src/lib.rs）与同一套 Web 前端被两个入口共用，不会出现两套行为。

## 特性

- **规则管理**：公网域名 ↔ 本地端口，增删改与排序
- **保存即校验**：写入 cloudflared 配置后调用 ingress validate，配错当场报错
- **隧道启停**：接管 cloudflared 子进程，日志实时可见
- **DNS 同步**（可选）：用 Cloudflare API Token 自动创建/更新 CNAME 到 <tunnel-id>.cfargotunnel.com
- **状态不说谎**：区分「本面板启动」与「外部已有进程」
- **深/浅色主题**：跟随系统，可手动切换并记住
- **手机可用**：窄屏自动切卡片布局
- **性能监测**：CPU / 内存 / 磁盘 / 负载 / 网速 / 面板自身占用
- **首页实时监控**：CPU、内存、系统磁盘、上下行速率直接显示在首页；状态与指标分别轮询，云端查询在后台每 30 秒更新，失败时保留上次列表并显示提示。
- **移动端底栏**：首页、连接、API、监控、日志固定在底部，兼容设备安全区；桌面继续使用侧栏。
- **工作区布局**：隧道与规则、连接设置、API 与流式优化、运行监控、连接日志分区；统一下拉框、开关、弹窗及键盘操作
- **实时系统主题**：浅色 / 深色 / 跟随系统，登录页和控制台共用设置，系统主题变化即时响应
- **连接参数**：HTTP2（默认推荐）/ auto / QUIC、IPv4 / IPv6 / auto、全局 / us 区域、日志级别；保存后可手动重启应用
- **源站高级参数**：逐条规则设置连接/TLS 超时、TCP 保活、空闲连接、HTTP/2 回源、分块传输、Host 和 SNI
- **云端 API 优化**：按域名和路径前缀设置缓存绕过、请求体/响应体缓冲及 Rocket Loader；读取并逐项修改 Zone 的 SSL、强制 HTTPS 与 Rocket Loader
- **SSE 工具**：生成 Nginx 流式透传模板，展示云端规则 JSON，日志搜索与自动滚动开关

Windows 托盘版：只有托盘图标，不再有 GUI 窗口，面板在浏览器里打开；退出托盘会停掉服务端。

服务端额外能力：网页界面、**口令 + 访问令牌双因子**登录、按 IP 的**防爆破锁定**、CSRF 防护、安全响应头。

## 目录

```
cf-tunnel-panel/
  src/lib.rs            共用核心（配置 / cloudflared / 端口 / DNS）
   src/bin/tray.rs       Windows 托盘版（tray-icon + muda，拉起本地服务端）
  src/bin/server.rs     服务端（tiny_http + argon2）
  web-src/              网页前端源码（Vue 3 + Tailwind + shadcn 风格组件）
  web/                  前端构建产物（编进二进制，已提交）
```

## 网页前端

服务端界面是 Vue 3 + Tailwind + shadcn 风格组件（Button / Card / Input / Label / Badge），
构建产物 web/index.html、web/app.js、web/style.css 已提交，因此**只编 Rust 不需要 Node**。

要改前端时：

```bash
cd web-src
npm install
npm run typecheck  # Vue / TypeScript 类型检查
npm run build      # 产物直接写回 ../web，文件名固定为 app.js / style.css
```

只有在重建前端后才需要重新 cargo build（产物是用 include_str! 编进二进制的）。

### 配置的生效范围

- **连接设置**写入当前隧道 YAML，并传给本地和 Token 两种启动方式。保存不会中断连接，可在保存后点击「重启并应用已保存配置」。
- **源站高级参数**写入对应 ingress 的 `originRequest`。HTTP/2 回源需要 HTTPS。Token 远程管理模式的 ingress 以 Cloudflare 云端为准，界面会明确提示。
- **切换隧道**前先停止当前连接器。每个隧道读取自己的规则、连接配置和 Token；面板会记住选中的配置路径。
- **Cloudflare API Token** 按需授予 Zone Read、DNS Edit、Zone Settings Read/Edit、Cache Rules Edit、Config Settings Write。缺少权限、功能或配额时展示 API 错误，不会显示为已应用。
- **云端规则**仅新增或更新面板创建的同域名/路径规则，不替换整个规则集。路径或域名变化会创建另一条规则，旧规则可到 Cloudflare 后台管理。其他规则的执行顺序仍可能覆盖结果。
- **请求/响应缓冲 None** 会影响依赖相应报文体检查的功能，应用前需确认该影响；默认不主动修改。Zone 级设置影响全部子域，修改前会展示具体变更。
- **Nginx 模板**供复制到源站部署；面板不会自动修改应用响应头，也不保证固定延迟收益。没有加入 `region: apac`、`originRequest.compression` 等不受支持的参数。

官方参数与规则说明：

- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/run-parameters/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/origin-parameters/
- https://developers.cloudflare.com/rules/configuration-rules/settings/
- https://developers.cloudflare.com/cache/how-to/cache-rules/create-api/

## 前置条件

1. 安装 cloudflared
   - Windows：winget install Cloudflare.cloudflared
   - Ubuntu：按官方文档添加源后 apt install cloudflared
2. 完成一次授权并创建隧道：

```bash
cloudflared tunnel login            # 浏览器里授权你的域名
cloudflared tunnel create my-tunnel # 生成 <tunnel-id>.json 凭据
```

3. 把域名 CNAME 指向 <tunnel-id>.cfargotunnel.com（桌面版的「同步 DNS 记录」可代劳）

## 托盘版（Windows）

```bash
cargo build --release                                           # 托盘
cargo build --release --no-default-features --features server --bin cf-tunnel-server
# 产物：target/release/cf-tunnel-panel.exe（托盘，约 350 KB）
#       target/release/cf-tunnel-server.exe（Web 服务端，约 2 MB）
```

两个 exe 放**同一目录**，双击 `cf-tunnel-panel.exe`：

- 托盘出现图标，**不弹任何窗口**（PE 子系统是 GUI，无控制台）
- 左键点图标出菜单：打开面板 / 复制面板地址 / 打开配置目录 / 退出
- 面板在浏览器打开：`http://127.0.0.1:8788/`，与 Linux 服务端是同一套 Web UI
- 首次运行自动生成口令，写入 `%USERPROFILE%\.cloudflared\panel-desktop-password.txt`；
  访问令牌用 `cf-tunnel-server.exe --print-token` 查看
- 托盘用隐藏窗口方式拉起服务端（只监听 127.0.0.1）；退出托盘会一并停掉服务端
- 运行日志：`%USERPROFILE%\.cloudflared\tray.log`

规则与凭据仍按隧道分开存放：`%USERPROFILE%\.cloudflared\panels\<tunnel-id>.yml`。

开机自启：把 `cf-tunnel-panel.exe` 的快捷方式放进 `shell:startup`（无控制台窗口，静默常驻）。

## 服务端（Ubuntu 等 Linux）

### 构建

```bash
sudo apt install -y build-essential pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
cargo build --release --no-default-features --features server --bin cf-tunnel-server
# 产物：target/release/cf-tunnel-server（约 2 MB，无 GUI 依赖）
```

### 初始化与启动

```bash
sudo mkdir -p /etc/cf-tunnel-panel
export PANEL_CONFIG=/etc/cf-tunnel-panel/panel.json
PANEL_PASSWORD='换成你的口令' sudo -E ./cf-tunnel-server --set-password
sudo -E ./cf-tunnel-server --print-token     # 访问令牌，登录时需要
sudo -E ./cf-tunnel-server --bind 127.0.0.1 --port 8788
```

首次运行会自动生成访问令牌并写入配置文件（权限 600）。口令用 Argon2id 存哈希，不落明文。

可选环境变量：TUNNEL_CONFIG 指定 cloudflared 的 yml 路径；PANEL_CONFIG 指定面板自身配置。

### systemd

```ini
[Unit]
Description=Cloudflare Tunnel Panel
After=network-online.target

[Service]
Type=simple
Environment=PANEL_CONFIG=/etc/cf-tunnel-panel/panel.json
Environment=TUNNEL_CONFIG=/home/<user>/.cloudflared/my-tunnel.yml
ExecStart=/usr/local/bin/cf-tunnel-server --bind 127.0.0.1 --port 8788
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

### 反向代理 + 防爆破（必须）

面板自身只绑 127.0.0.1。对外请用 nginx，并在代理层再加一层限速——应用层锁定拦不住分布式尝试。

```nginx
# /etc/nginx/conf.d/panel.conf
limit_req_zone $binary_remote_addr zone=panel_login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=panel_api:10m rate=30r/s;

server {
    listen 443 ssl http2;
    server_name panel.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location = /login {
        limit_req zone=panel_login burst=3 nodelay;
        proxy_pass http://127.0.0.1:8788;
        include /etc/nginx/proxy_params;
    }

    location / {
        limit_req zone=panel_api burst=60 nodelay;
        proxy_pass http://127.0.0.1:8788;
        proxy_set_header X-Forwarded-For $remote_addr;
        include /etc/nginx/proxy_params;
    }
}
```

反代后要在面板配置里把 trust_proxy 设为 true，否则应用层锁定看到的是 nginx 的地址。

## 安全说明

- 服务端默认只监听 127.0.0.1，不要直接暴露到公网
- 登录需要**口令 + 访问令牌**两项，缺一不可
- 连续失败达到阈值（默认 5 次 / 10 分钟窗口）后锁定 15 分钟，锁定期间即使口令正确也拒绝
- 所有写操作要求 X-CSRF 头与会话绑定；会话 Cookie 为 HttpOnly; SameSite=Lax
- 响应带 CSP、X-Frame-Options: DENY、nosniff、Referrer-Policy: no-referrer
- cf-api.token、<tunnel-id>.json、cert.pem 都是机密文件（权限 600），**不要提交到仓库**

## 测试

```bash
cargo test --no-default-features --features server
cargo build --release --no-default-features --features server --bin cf-tunnel-server
```

核心测试覆盖配置往返、域名校验、端口探测、gate 双向（合法配置通过 / 缺 catch-all 必须判红）、
BOM 容错、token 文件读写、zone 归属匹配。

## 已知限制

- cloudflared 没有请求体大小配置项；上限由 Cloudflare 套餐决定（Free 为 100 MB）
- 桌面版内存约 130 MB 起步，主要来自系统 CJK 字体（约 19 MB）与 OpenGL 驱动
- 服务端未内置 TLS，请务必用 nginx/caddy 终止 TLS
- 旧的 Python 版（tkinter）已被 Rust 版取代并删除

## 第三方资源

托盘/窗口图标取自 eframe(egui) 自带的 `data/icon.png`，已转为 `assets/tray-32.rgba` 编进二进制，
使托盘与任务栏图标保持一致。该素材随 egui/eframe 以 MIT 或 Apache-2.0 双许可发布，与本项目的 GPL-3.0 兼容。

## 性能说明

隧道延迟主要由 Cloudflare 把连接器分配到哪个 PoP 决定。若连接器被分配到远端（例如国内网络常被分到 lax），
每个请求都要跨太平洋往返，实测空请求 TTFB 约 0.6–1s 就是这个原因，不是面板或源站的问题。

面板默认使用 HTTP2 + IPv4，新建配置和未指定协议的配置均以 HTTP2 为推荐基线；已有显式保存的 auto / QUIC 选择仍保留，不强制覆盖。HTTP2 不保证在所有网络中最快。面板保留 IPv4 默认值，可在连接设置中改为 IPv6 或自动。传输协议、网络路径、请求大小和源站处理都会影响延迟，
应分别测量上传、首字节、首个 SSE 事件耗时后调整配置。

## 许可证

GPL-3.0-or-later，见 LICENSE。衍生作品需同样开源。

### 访问诊断与一键优化

右上角「访问诊断」提供两个来源：当前设备浏览器（手机/电脑 → 公网域名）与面板主机内部（服务器 → 公网域名）。均为匿名 HTTPS GET，仅测响应头，不是整页/SSE 首事件速度。浏览器跨域可能隐藏状态码、DNS、TLS、TTFB，收到响应不等于服务健康。内部探测使用主机原生 curl，不跟随重定向；Linux 需安装 curl（Ubuntu: apt install curl），Windows 使用系统 curl.exe。

为测试填写网络名称与轮次名；最近 30 轮保存在当前浏览器的 localStorage，刷新或切换网络保留，可清空或导出。图表区分浏览器与服务器，只有同目标、类型、采样次数和超时设置的完整结果参与比较；标签不会自动改变网络。

一键连接优化先预览，仅更改协议并保留现有 IP/区域/日志参数；经 cloudflared 校验后保存，可显式勾选重启。保存时检查旧配置指纹，启动失败尝试还原旧配置。API/SSE 一键优化仅创建指定路径前缀的缓存绕过规则，需要 Cloudflare Zone Read 与 Cache Rules Edit 权限；不会自动关闭源站缓冲、改 DNS 或缓存用户数据。

### 监控历史与告警

面板后台每分钟采集 CPU、内存、系统磁盘、负载和上下行速率，无需保持网页打开。与 PANEL_CONFIG 同目录的 monitoring/metrics 和 monitoring/events 按 UTC 日期存 JSONL，自动保留 90 天；浏览器按当前设备时区的日、周、月或自定义日期范围查询。记录从本功能启用起开始，不补造过去数据。长周期图表最多显示 1,200 个实际采样点，分钟原始记录仍保留。

告警默认 CPU >85%、内存 >90%、磁盘 >90%，连续 5 分钟触发，每个指标每小时最多通知一次；采样间断超过 90 秒会重新累计。资源恢复写日志，冷却保留。通知默认关闭，首个渠道支持 PushPlus。Token 仅保存在 monitoring/pushplus.token（Linux 权限 0600），alerts.json 不含密钥，接口不回显。未配置有效 Token 无法启用通知，测试通知需显式点击；PushPlus 接受请求不保证终端最终送达。告警日志包含超限、恢复、配置变更、发送成功/失败，跟随所选日期范围。

图表全部使用 Apache ECharts 的 Canvas renderer，未手写 SVG 图表。快速连接页先提供可理解的方案与影响说明，高级参数默认折叠。

### 配置作用范围与反馈

- 总览每条规则的“API / 流式”按钮会带入该公网子域。API 页面可从已有转发域名快捷选择；切换目标会重置未应用的路径/缓冲草稿，避免误操作。
- 缓存绕过、缓冲、路径 Rocket Loader 作用于所选子域 + 路径前缀；`/` 表示此子域全部路径，不是全部转发规则。
- SSL、强制 HTTPS、全局 Rocket Loader 属于整个 Cloudflare Zone 设置，影响所有子域；单独放在默认收起的高级区，读取后显示实际 Zone 名称。Nginx 模板仅供部署到对应源站，不自动应用。
- 告警保存、测试通知、清除令牌的成功/失败均使用可关闭 Toast；手机 Toast 位于底部导航上方，不必滚回页顶寻找反馈。

### Windows 托盘本机免密

Windows 托盘启动的面板服务只监听 `127.0.0.1:8788`，并通过内部环境标记启用回环免密：本机打开 `http://127.0.0.1:8788/` 可直接进入，不需要口令和访问令牌。该模式不写入 `panel.json`，只由托盘进程设置；如果服务监听到非回环地址则自动失效。Linux/J1900 服务端和公网反代仍强制口令 + 访问令牌。
