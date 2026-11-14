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
npm run build      # 产物直接写回 ../web，文件名固定为 app.js / style.css
```

只有在重建前端后才需要重新 cargo build（产物是用 include_str! 编进二进制的）。

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
Environment=TUNNEL_CONFIG=/root/.cloudflared/my-tunnel.yml
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
cargo test --no-default-features --lib
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

面板在启动 cloudflared 时会带 --edge-ip-version 4：本机 IPv6 到 Cloudflare 边缘会超时（每次约 10s 后重连），
是偶发十几秒卡顿的元凶，强制 IPv4 后不再出现。

## 许可证

GPL-3.0-or-later，见 LICENSE。衍生作品需同样开源。
