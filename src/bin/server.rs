//! 服务端面板: 在服务器上跑, 用浏览器管理 Cloudflare Tunnel。
//!
//! 安全设计:
//! - 登录需要「口令 + 访问令牌」两项, 口令用 Argon2id 存哈希, 令牌用常数时间比较
//! - 防爆破: 按来源 IP 的滑动窗口, 超限锁定一段时间; 失败统一延迟响应
//! - 会话: 随机 32 字节 id, 内存保存, 空闲超时; Cookie 带 HttpOnly/SameSite
//! - CSRF: 每个会话一个令牌, 所有写操作必须带 X-CSRF 头
//! - 响应统一带 CSP / X-Frame-Options / nosniff 等安全头
//! - 默认只绑 127.0.0.1, 对外请用 nginx 反代并加 limit_req

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server};

use cf_tunnel_panel as core;

const INDEX_HTML: &str = include_str!("../../web/index.html");
const APP_JS: &str = include_str!("../../web/app.js");
const STYLE_CSS: &str = include_str!("../../web/style.css");

const MAX_BODY: usize = 64 * 1024;
const MAX_LOGS: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PanelConfig {
    bind: String,
    port: u16,
    password_hash: String,
    access_token: String,
    session_ttl_min: u64,
    max_fails: u32,
    window_min: u64,
    lock_min: u64,
    trust_proxy: bool,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".into(),
            port: 8788,
            password_hash: String::new(),
            access_token: String::new(),
            // 登录有效期 7 天; 浏览器 cookie 的 Max-Age 也用它,
            // 原来是 30 分钟且不随活跃滑动, 挂一会儿就被踢
            session_ttl_min: 10080,
            max_fails: 5,
            window_min: 10,
            lock_min: 15,
            trust_proxy: false,
        }
    }
}

fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("PANEL_CONFIG") {
        return PathBuf::from(p);
    }
    core::cf_dir().join("panel.json")
}

/// 运行状态的落盘位置，和 PANEL_CONFIG 放同一目录。
fn run_state_path() -> PathBuf {
    let mut p = config_path();
    p.set_file_name("state.json");
    p
}

fn load_config(path: &PathBuf) -> std::io::Result<PanelConfig> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(serde_json::from_str(&t).unwrap_or_default()),
        Err(_) => Ok(PanelConfig::default()),
    }
}

fn save_config(path: &PathBuf, cfg: &PanelConfig) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(cfg).unwrap())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_password(pw: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| format!("salt: {e}"))?;
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("hash: {e}"))
}

fn verify_password(stored: &str, pw: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(pw.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// 常数时间比较, 避免按前缀长度泄露信息。
fn ct_eq(a: &str, b: &str) -> bool {
    let (x, y) = (a.as_bytes(), b.as_bytes());
    if x.len() != y.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..x.len() {
        diff |= x[i] ^ y[i];
    }
    diff == 0
}

#[derive(Clone)]
struct Session {
    csrf: String,
    /// unix 秒; 用墙钟是为了能落盘, Instant 无法跨进程保存
    last: u64,
    /// 口令哈希指纹; 改口令后旧会话指纹对不上, 自动失效
    pw_fp: String,
}

/// 取口令哈希的指纹。
/// 取整串哈希的尾部 16 字符: argon2 每次设置口令都会生成新盐, 摘要也随之改变,
/// 所以只要口令被重新设置过（哪怕是同一个口令）, 指纹必然变化。
fn pw_fingerprint(hash: &str) -> String {
    let s = hash.trim();
    let n = s.chars().count();
    s.chars().skip(n.saturating_sub(16)).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ttl_secs_from(cfg: &PanelConfig) -> u64 {
    cfg.session_ttl_min.max(1) as u64 * 60
}

/// 启动隧道: 配了连接器 token 就走 token 模式, 否则用本地 yml 配置。
fn spawn_tunnel(
    runner: &mut core::TunnelRunner,
    cf: &Path,
    tcfg: &core::TunnelConfig,
) -> std::io::Result<()> {
    match core::read_tunnel_token(&tcfg.path) {
        Some(token) => runner.start_with_token(cf, &token),
        None => runner.start(cf, &tcfg.path),
    }
}

fn sessions_path() -> PathBuf {
    let mut p = config_path();
    p.set_file_name("sessions.json");
    p
}

fn save_sessions_to(path: &Path, sessions: &HashMap<String, Session>) {
    let mut obj = serde_json::Map::new();
    for (sid, s) in sessions {
        obj.insert(
            sid.clone(),
            serde_json::json!({ "csrf": s.csrf, "last": s.last, "pw": s.pw_fp }),
        );
    }
    let body = serde_json::Value::Object(obj).to_string();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, body);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn load_sessions_from(path: &Path, ttl: u64) -> HashMap<String, Session> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return out;
    };
    let Some(obj) = v.as_object() else {
        return out;
    };
    let now = now_unix();
    for (sid, item) in obj {
        let csrf = item.get("csrf").and_then(|x| x.as_str()).unwrap_or("");
        let last = item.get("last").and_then(|x| x.as_u64()).unwrap_or(0);
        let pw_fp = item.get("pw").and_then(|x| x.as_str()).unwrap_or("");
        if csrf.is_empty() || last == 0 {
            continue;
        }
        // 过期的会话不恢复, 否则等于把 TTL 作废
        if now.saturating_sub(last) > ttl {
            continue;
        }
        out.insert(sid.clone(), Session { csrf: csrf.to_owned(), last, pw_fp: pw_fp.to_owned() });
    }
    out
}

#[derive(Default)]
struct FailEntry {
    count: u32,
    window_start: Option<Instant>,
    locked_until: Option<Instant>,
}

/// 上一次采样，用来算 CPU 占用与网速（避免在请求里 sleep）。
#[derive(Default)]
struct MetricsPrev {
    cpu: Option<(u64, u64)>,
    net: Option<(u64, u64)>,
    at: Option<std::time::Instant>,
    cpu_pct: f64,
    rx_bps: f64,
    tx_bps: f64,
}

struct State {
    cfg: Mutex<PanelConfig>,
    metrics: Mutex<MetricsPrev>,
    sessions: Mutex<HashMap<String, Session>>,
    fails: Mutex<HashMap<IpAddr, FailEntry>>,
    runner: Mutex<core::TunnelRunner>,
    tunnel: Mutex<core::TunnelConfig>,
    logs: Mutex<Vec<String>>,
    cf: Option<PathBuf>,
    /// 连接状态缓存: tunnel info 要走网络, 不能每次请求都算
    conn: Mutex<String>,
}

impl State {
    fn ttl(&self) -> u64 {
        ttl_secs_from(&self.cfg.lock().unwrap())
    }

    /// 把当前会话表写盘（登录/登出/续期时调用）。
    fn persist_sessions(&self) {
        let map = {
            let g = self.sessions.lock().unwrap();
            g.clone()
        };
        save_sessions_to(&sessions_path(), &map);
    }

    fn log(&self, line: impl Into<String>) {
        let mut logs = self.logs.lock().unwrap();
        logs.push(line.into());
        if logs.len() > MAX_LOGS {
            let drop = logs.len() - MAX_LOGS;
            logs.drain(0..drop);
        }
    }

    /// 剩余锁定秒数; None 表示未被锁。
    fn locked(&self, ip: IpAddr) -> Option<u64> {
        let fails = self.fails.lock().unwrap();
        let e = fails.get(&ip)?;
        let until = e.locked_until?;
        let now = Instant::now();
        if until > now {
            Some((until - now).as_secs().max(1))
        } else {
            None
        }
    }

    fn record_failure(&self, ip: IpAddr) {
        let cfg = self.cfg.lock().unwrap().clone();
        let mut fails = self.fails.lock().unwrap();
        let now = Instant::now();
        let e = fails.entry(ip).or_default();
        match e.window_start {
            Some(start) if now.duration_since(start).as_secs() < cfg.window_min * 60 => {
                e.count += 1;
            }
            _ => {
                e.window_start = Some(now);
                e.count = 1;
            }
        }
        if e.count >= cfg.max_fails {
            e.locked_until = Some(now + Duration::from_secs(cfg.lock_min * 60));
            e.count = 0;
            e.window_start = Some(now);
            self.log(format!("登录失败次数超限, 已锁定 {ip} {} 分钟", cfg.lock_min));
        }
    }

    fn record_success(&self, ip: IpAddr) {
        self.fails.lock().unwrap().remove(&ip);
    }

    fn create_session(&self) -> (String, String) {
        let sid = rand_hex(32);
        let csrf = rand_hex(24);
        self.sessions.lock().unwrap().insert(
            sid.clone(),
            Session {
                csrf: csrf.clone(),
                last: now_unix(),
                pw_fp: pw_fingerprint(&self.cfg.lock().unwrap().password_hash),
            },
        );
        self.persist_sessions();
        (sid, csrf)
    }

    /// 校验会话并滑动续期; 命中时顺便返回 csrf。
    fn touch_session(&self, sid: &str) -> Option<String> {
        let ttl = self.ttl();
        let expect_fp = pw_fingerprint(&self.cfg.lock().unwrap().password_hash);
        let now = now_unix();
        let mut need_save = false;
        let mut out = None;
        {
            let mut sessions = self.sessions.lock().unwrap();
            let verdict = sessions.get(sid).map(|s| {
                let age = now.saturating_sub(s.last);
                (age > ttl, s.pw_fp != expect_fp, age >= 300)
            });
            match verdict {
                None => {}
                Some((expired, fp_bad, stale)) => {
                    if expired || fp_bad {
                        // 过期, 或口令改过: 立即作废
                        sessions.remove(sid);
                        need_save = true;
                    } else {
                        need_save = stale;
                        if let Some(s) = sessions.get_mut(sid) {
                            s.last = now;
                            out = Some(s.csrf.clone());
                        }
                    }
                }
            }
        }
        if need_save {
            self.persist_sessions();
        }
        out
    }

    fn drop_session(&self, sid: &str) {
        self.sessions.lock().unwrap().remove(sid);
        self.persist_sessions();
    }
}

// ------------------------------------------------------------------ HTTP 工具

fn hdr(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("header")
}

fn security_headers() -> Vec<Header> {
    vec![
        hdr(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
        hdr("X-Frame-Options", "DENY"),
        hdr("X-Content-Type-Options", "nosniff"),
        hdr("Referrer-Policy", "no-referrer"),
        hdr("Cache-Control", "no-store"),
    ]
}

fn send(req: Request, status: u16, ctype: &str, body: &[u8], extra: Vec<Header>) {
    let mut resp = Response::from_data(body.to_vec()).with_status_code(status);
    resp.add_header(hdr("Content-Type", ctype));
    for h in security_headers() {
        resp.add_header(h);
    }
    for h in extra {
        resp.add_header(h);
    }
    let _ = req.respond(resp);
}

fn send_json(req: Request, status: u16, v: serde_json::Value) {
    let body = serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec());
    send(req, status, "application/json; charset=utf-8", &body, vec![]);
}

fn send_text(req: Request, status: u16, msg: &str) {
    send(req, status, "text/plain; charset=utf-8", msg.as_bytes(), vec![]);
}

fn read_body(req: &mut Request) -> String {
    let mut s = String::new();
    let _ = req.as_reader().take(MAX_BODY as u64).read_to_string(&mut s);
    s
}

fn cookie(req: &Request, name: &str) -> Option<String> {
    for h in req.headers() {
        if h.field.equiv("Cookie") {
            for part in h.value.as_str().split(';') {
                let part = part.trim();
                if let Some(rest) = part.strip_prefix(&format!("{name}=")) {
                    return Some(rest.to_owned());
                }
            }
        }
    }
    None
}

fn client_ip(req: &Request, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        for h in req.headers() {
            if h.field.equiv("X-Forwarded-For") {
                if let Some(first) = h.value.as_str().split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }
    // tiny_http 0.12 的 remote_addr 是 Option
    req.remote_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn json_of(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
}

// ------------------------------------------------------------------ 路由

fn handle(st: &Arc<State>, req: Request) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_owned();
    let trust_proxy = st.cfg.lock().unwrap().trust_proxy;
    let ip = client_ip(&req, trust_proxy);

    // 浏览器会自动请求 favicon, 直接给空响应, 避免日志里刷 404
    if path == "/favicon.ico" {
        send(req, 204, "image/x-icon", b"", vec![]);
        return;
    }

    // 静态资源不需要登录
    let asset = match path.as_str() {
        "/app.js" => Some(("application/javascript; charset=utf-8", APP_JS)),
        "/style.css" => Some(("text/css; charset=utf-8", STYLE_CSS)),
        _ => None,
    };
    if let Some((ctype, body)) = asset {
        send(req, 200, ctype, body.as_bytes(), vec![]);
        return;
    }

    if path == "/login" {
        if method == Method::Get {
            // 前端按 pathname 路由, 登录页与面板共用同一个 HTML 外壳
            send(req, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes(), vec![]);
        } else {
            handle_login(st, req, ip);
        }
        return;
    }

    if path == "/logout" && method == Method::Post {
        let csrf_ok = cookie(&req, "sid")
            .and_then(|sid| st.touch_session(&sid))
            .map(|c| {
                req.headers()
                    .iter()
                    .any(|h| h.field.equiv("X-CSRF") && ct_eq(h.value.as_str(), &c))
            })
            .unwrap_or(false);
        if !csrf_ok {
            send_json(req, 403, serde_json::json!({"error": "CSRF 校验失败"}));
            return;
        }
        if let Some(sid) = cookie(&req, "sid") {
            st.drop_session(&sid);
        }
        send(
            req,
            200,
            "application/json; charset=utf-8",
            b"{\"ok\":true}",
            vec![hdr("Set-Cookie", "sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")],
        );
        return;
    }

    // 其余都要会话
    let Some(sid) = cookie(&req, "sid") else {
        if path.starts_with("/api/") {
            send_json(req, 401, serde_json::json!({"error": "未登录"}));
        } else {
            send(
                req,
                302,
                "text/plain; charset=utf-8",
                b"",
                vec![hdr("Location", "/login")],
            );
        }
        return;
    };
    let Some(csrf) = st.touch_session(&sid) else {
        if path.starts_with("/api/") {
            send_json(req, 401, serde_json::json!({"error": "会话已过期"}));
        } else {
            send(
                req,
                302,
                "text/plain; charset=utf-8",
                b"",
                vec![hdr("Location", "/login")],
            );
        }
        return;
    };

    if path == "/" {
        send(req, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes(), vec![]);
        return;
    }

    if path.starts_with("/api/") {
        let is_write = method != Method::Get;
        if is_write {
            // 写操作必须带匹配的 CSRF 头
            let ok = req
                .headers()
                .iter()
                .any(|h| h.field.equiv("X-CSRF") && ct_eq(h.value.as_str(), &csrf));
            if !ok {
                send_json(req, 403, serde_json::json!({"error": "CSRF 校验失败"}));
                return;
            }
        }
        handle_api(st, req, &path, &method, &csrf);
        return;
    }

    send_text(req, 404, "not found");
}

fn handle_login(st: &Arc<State>, mut req: Request, ip: IpAddr) {
    if let Some(secs) = st.locked(ip) {
        st.log(format!("{ip} 处于锁定状态, 拒绝登录"));
        let body = serde_json::json!({"error": format!("尝试过多, 请 {secs} 秒后再试")});
        let mut resp = Response::from_data(serde_json::to_vec(&body).unwrap()).with_status_code(429);
        resp.add_header(hdr("Content-Type", "application/json; charset=utf-8"));
        resp.add_header(hdr("Retry-After", &secs.to_string()));
        for h in security_headers() {
            resp.add_header(h);
        }
        let _ = req.respond(resp);
        return;
    }

    let body = read_body(&mut req);
    let v = json_of(&body);
    let pw = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
    let tk = v.get("token").and_then(|x| x.as_str()).unwrap_or("");
    let cfg = st.cfg.lock().unwrap().clone();

    let pw_ok = !cfg.password_hash.is_empty() && verify_password(&cfg.password_hash, pw);
    let tk_ok = !cfg.access_token.is_empty() && ct_eq(tk, &cfg.access_token);

    if !(pw_ok && tk_ok) {
        st.record_failure(ip);
        st.log(format!("登录失败 ip={ip}（口令{} 令牌{}）",
            if pw_ok { "对" } else { "错" },
            if tk_ok { "对" } else { "错" }));
        // 统一延迟, 拖慢自动化尝试
        std::thread::sleep(Duration::from_millis(400));
        send_json(req, 401, serde_json::json!({"error": "口令或访问令牌不正确"}));
        return;
    }

    st.record_success(ip);
    let (sid, csrf) = st.create_session();
    st.log(format!("登录成功 ip={ip}"));
    let cookie = format!(
        "sid={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        st.cfg.lock().unwrap().session_ttl_min * 60
    );
    send(
        req,
        200,
        "application/json; charset=utf-8",
        serde_json::to_vec(&serde_json::json!({"ok": true, "csrf": csrf})).unwrap().as_slice(),
        vec![hdr("Set-Cookie", &cookie)],
    );
}

fn handle_api(st: &Arc<State>, mut req: Request, path: &str, method: &Method, csrf: &str) {
    let _ = csrf;
    match (method, path) {
        (Method::Get, "/api/state") => {
            let tcfg = st.tunnel.lock().unwrap().clone();
            let tunnels = match &st.cf {
                Some(cf) => core::list_tunnels(cf).unwrap_or_default(),
                None => Vec::new(),
            };
            let rules: Vec<serde_json::Value> = tcfg
                .rules
                .iter()
                .map(|r| {
                    let (scheme, host, port) = core::split_service(&r.service)
                        .unwrap_or_else(|| ("http".to_owned(), "127.0.0.1".to_owned(), 0u16));
                    let open = port != 0 && core::tcp_open(&host, port);
                    serde_json::json!({
                        "hostname": r.hostname,
                        "service": r.service,
                        "scheme": scheme,
                        "host": host,
                        "port": port,
                        "noTlsVerify": r.no_tls_verify,
                        "enabled": r.enabled,
                        "note": r.note,
                        "port_open": open,
                    })
                })
                .collect();
            let running = st.runner.lock().unwrap().running();
            let external = !running && core::external_running();
            let conn = st.conn.lock().unwrap().clone();
            let logs = st.logs.lock().unwrap().clone();
            let tlist: Vec<serde_json::Value> = tunnels
                .iter()
                .map(|t| serde_json::json!({"id": t.id, "name": t.name}))
                .collect();
            let body = serde_json::json!({
                "tunnel": tcfg.tunnel,
                "tunnels": tlist,
                "rules": rules,
                "running": running,
                "external": external,
                "conn": conn,
                "config_path": tcfg.path.display().to_string(),
                "has_cf_token": core::read_token().is_some(),
                "cf_token_path": core::token_path().display().to_string(),
                "has_tunnel_token": core::read_tunnel_token(&tcfg.path).is_some(),
                "tunnel_token_path": core::tunnel_token_path(&tcfg.path).display().to_string(),
                "logs": logs,
                "csrf": csrf,
            });
            send_json(req, 200, body);
        }
        (Method::Post, "/api/rules") => {
            let body = read_body(&mut req);
            let v = json_of(&body);
            let Some(arr) = v.get("rules").and_then(|x| x.as_array()) else {
                send_json(req, 400, serde_json::json!({"error": "缺少 rules"}));
                return;
            };
            let mut rules = Vec::new();
            for item in arr {
                let host = item.get("hostname").and_then(|x| x.as_str()).unwrap_or("").trim().to_ascii_lowercase();
                let port = item.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
                if let Err(e) = core::validate_hostname(&host) {
                    send_json(req, 400, serde_json::json!({"error": format!("{host}: {e}")}));
                    return;
                }
                let svc_raw = item.get("service").and_then(|x| x.as_str()).unwrap_or("").trim().to_owned();
                let no_tls = item.get("noTlsVerify").and_then(|x| x.as_bool()).unwrap_or(false);
                let origin_host = item.get("host").and_then(|x| x.as_str()).unwrap_or("127.0.0.1").trim().to_owned();
                let scheme = item.get("scheme").and_then(|x| x.as_str()).unwrap_or("http").trim().to_ascii_lowercase();
                let service = if !svc_raw.is_empty() {
                    if !(svc_raw.starts_with("http://") || svc_raw.starts_with("https://")) {
                        send_json(req, 400, serde_json::json!({"error": format!("{host}: service 必须以 http:// 或 https:// 开头")}));
                        return;
                    }
                    svc_raw
                } else {
                    if port == 0 || port > 65535 {
                        send_json(req, 400, serde_json::json!({"error": format!("{host}: 端口不合法")}));
                        return;
                    }
                    format!("{scheme}://{origin_host}:{port}")
                };
                if rules.iter().any(|r: &core::Rule| r.hostname == host) {
                    send_json(req, 400, serde_json::json!({"error": format!("{host} 重复")}));
                    return;
                }
                let enabled = item.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
                let note = item.get("note").and_then(|x| x.as_str()).unwrap_or("").trim().to_owned();
                rules.push(core::Rule {
                    hostname: host,
                    service,
                    no_tls_verify: no_tls,
                    enabled,
                    note,
                });
            }
            st.tunnel.lock().unwrap().rules = rules.clone();
            match core::write_rules_sidecar(&core::rules_sidecar(&st.tunnel.lock().unwrap().path), &rules) {
                Ok(()) => st.log(format!("规则已更新（{} 条, 已保存清单）", rules.len())),
                Err(e) => st.log(format!("规则已更新, 但清单写入失败: {e}")),
            }
            send_json(req, 200, serde_json::json!({"ok": true}));
        }
        (Method::Post, "/api/tunnel") => {
            let body = read_body(&mut req);
            let v = json_of(&body);
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_owned();
            if id.is_empty() {
                send_json(req, 400, serde_json::json!({"error": "缺少隧道 id"}));
                return;
            }
            {
                let mut t = st.tunnel.lock().unwrap();
                t.tunnel = id.clone();
                t.credentials_file = core::cf_dir()
                    .join(format!("{id}.json"))
                    .to_string_lossy()
                    .into_owned();
            }
            st.log(format!("已切换到隧道 {id}"));
            send_json(req, 200, serde_json::json!({"ok": true}));
        }
        (Method::Post, "/api/save") => {
            let tcfg = st.tunnel.lock().unwrap().clone();
            if tcfg.tunnel.is_empty() {
                send_json(req, 400, serde_json::json!({"error": "还没选隧道"}));
                return;
            }
            if let Err(e) = core::write_config(&tcfg) {
                send_json(req, 500, serde_json::json!({"error": format!("写入失败: {e}")}));
                return;
            }
            st.log(format!("已写入 {}", tcfg.path.display()));
            let Some(cf) = st.cf.clone() else {
                send_json(req, 200, serde_json::json!({"ok": true, "output": "已保存（未找到 cloudflared，跳过校验）"}));
                return;
            };
            let _ = core::write_rules_sidecar(&core::rules_sidecar(&tcfg.path), &tcfg.rules);
            match core::validate_config(&cf, &tcfg.path) {
                Ok((true, out)) => {
                    st.log("配置校验通过");
                    // 配置变了, 正在跑的隧道必须重启才生效
                    let restarted = {
                        let mut runner = st.runner.lock().unwrap();
                        if runner.running() {
                            runner.stop();
                            match spawn_tunnel(&mut runner, &cf, &tcfg) {
                                Ok(()) => true,
                                Err(e) => {
                                    st.log(format!("重启隧道失败: {e}"));
                                    false
                                }
                            }
                        } else {
                            false
                        }
                    };
                    if restarted {
                        st.log("已按新配置重启隧道");
                    }
                    // 有 token 就顺手同步 DNS, 不用再点一次按钮
                    let mut dns_msgs: Vec<String> = Vec::new();
                    if let Some(token) = core::read_token() {
                        if !tcfg.tunnel.is_empty() {
                            for r in tcfg.rules.iter().filter(|r| r.enabled) {
                                match core::ensure_cname(&token, &r.hostname, &tcfg.tunnel) {
                                    Ok(m) => dns_msgs.push(m),
                                    Err(e) => dns_msgs.push(format!("{}: 失败 {e}", r.hostname)),
                                }
                            }
                            for m in &dns_msgs {
                                st.log(format!("DNS {m}"));
                            }
                        }
                    }
                    send_json(
                        req,
                        200,
                        serde_json::json!({"ok": true, "output": out, "restarted": restarted, "dns": dns_msgs}),
                    );
                }
                Ok((false, out)) => {
                    st.log(format!("配置校验失败: {out}"));
                    send_json(req, 400, serde_json::json!({"error": out}));
                }
                Err(e) => send_json(req, 500, serde_json::json!({"error": e.to_string()})),
            }
        }
        (Method::Post, "/api/start") => {
            let Some(cf) = st.cf.clone() else {
                send_json(req, 500, serde_json::json!({"error": "找不到 cloudflared"}));
                return;
            };
            let tcfg = st.tunnel.lock().unwrap().clone();
            if tcfg.rules.is_empty() {
                send_json(req, 400, serde_json::json!({"error": "还没有规则"}));
                return;
            }
            let mut runner = st.runner.lock().unwrap();
            if runner.running() {
                send_json(req, 200, serde_json::json!({"ok": true, "output": "已在运行"}));
                return;
            }
            match spawn_tunnel(&mut runner, &cf, &tcfg) {
                Ok(()) => {
                    let _ = core::write_run_state(&run_state_path(), true);
                    if core::read_tunnel_token(&tcfg.path).is_some() {
                        st.log("已按 token 模式启动隧道");
                    } else {
                        st.log("已启动隧道（本地配置）");
                    }
                    send_json(req, 200, serde_json::json!({"ok": true}));
                }
                Err(e) => send_json(req, 500, serde_json::json!({"error": format!("启动失败: {e}")})),
            }
        }
        (Method::Post, "/api/stop") => {
            st.runner.lock().unwrap().stop();
            let _ = core::write_run_state(&run_state_path(), false);
            st.log("已停止隧道");
            send_json(req, 200, serde_json::json!({"ok": true}));
        }
        (Method::Post, "/api/tunnel-token") => {
            let body = read_body(&mut req);
            let v = json_of(&body);
            let token = v
                .get("token")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_owned();
            let tcfg = st.tunnel.lock().unwrap().clone();
            let path = core::tunnel_token_path(&tcfg.path);
            if token.is_empty() {
                let _ = std::fs::remove_file(&path);
                st.log("已清除隧道 token, 回到本地配置模式");
                send_json(req, 200, serde_json::json!({"ok": true, "has_token": false}));
                return;
            }
            if token.len() < 20 {
                send_json(req, 400, serde_json::json!({"error": "隧道 token 太短, 请检查是否复制完整"}));
                return;
            }
            match core::write_tunnel_token(&tcfg.path, &token) {
                Ok(()) => {
                    st.log("已保存隧道 token（下次启动走 token 模式）");
                    send_json(req, 200, serde_json::json!({"ok": true, "has_token": true}));
                }
                Err(e) => send_json(
                    req,
                    500,
                    serde_json::json!({"error": format!("写入失败: {e}")}),
                ),
            }
        }
        (Method::Post, "/api/cf-token") => {
            let body = read_body(&mut req);
            let v = json_of(&body);
            let token = v
                .get("token")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_owned();
            if token.is_empty() {
                let path = core::token_path();
                let _ = std::fs::remove_file(&path);
                st.log("已清除 Cloudflare API Token");
                send_json(req, 200, serde_json::json!({"ok": true, "has_token": false}));
                return;
            }
            if token.len() < 20 {
                send_json(req, 400, serde_json::json!({"error": "Token 太短, 请检查是否复制完整"}));
                return;
            }
            match core::write_token_to(&core::token_path(), &token) {
                Ok(()) => {
                    st.log("已保存 Cloudflare API Token");
                    send_json(req, 200, serde_json::json!({"ok": true, "has_token": true}));
                }
                Err(e) => send_json(
                    req,
                    500,
                    serde_json::json!({"error": format!("写入失败: {e}")}),
                ),
            }
        }
        (Method::Post, "/api/dns") => {
            let Some(token) = core::read_token() else {
                send_json(req, 400, serde_json::json!({"error": "没有配置 API Token（写入 ~/.cloudflared/cf-api.token）"}));
                return;
            };
            let tcfg = st.tunnel.lock().unwrap().clone();
            if tcfg.tunnel.is_empty() || tcfg.rules.is_empty() {
                send_json(req, 400, serde_json::json!({"error": "需要隧道和规则"}));
                return;
            }
            let mut msgs = Vec::new();
            for r in &tcfg.rules {
                match core::ensure_cname(&token, &r.hostname, &tcfg.tunnel) {
                    Ok(m) => msgs.push(m),
                    Err(e) => msgs.push(format!("{}: 失败 {e}", r.hostname)),
                }
            }
            for m in &msgs {
                st.log(format!("DNS {m}"));
            }
            send_json(req, 200, serde_json::json!({"ok": true, "messages": msgs}));
        }
        (Method::Get, "/api/metrics") => {
            let now = std::time::Instant::now();
            let cpu_now = core::read_cpu_times();
            let net_now = core::read_net_totals();
            let (cpu_pct, rx_bps, tx_bps) = {
                let mut m = st.metrics.lock().unwrap();
                let dt = m
                    .at
                    .map(|t| now.duration_since(t).as_secs_f64())
                    .unwrap_or(0.0);
                if dt >= 0.5 {
                    if let (Some(prev), Some(cur)) = (m.cpu, cpu_now) {
                        let total = cur.1.saturating_sub(prev.1) as f64;
                        let idle = cur.0.saturating_sub(prev.0) as f64;
                        if total > 0.0 {
                            m.cpu_pct = ((total - idle) / total * 100.0).clamp(0.0, 100.0);
                        }
                    }
                    if let (Some(prev), Some(cur)) = (m.net, net_now) {
                        m.rx_bps = cur.0.saturating_sub(prev.0) as f64 / dt;
                        m.tx_bps = cur.1.saturating_sub(prev.1) as f64 / dt;
                    }
                    m.cpu = cpu_now;
                    m.net = net_now;
                    m.at = Some(now);
                } else if m.at.is_none() {
                    m.cpu = cpu_now;
                    m.net = net_now;
                    m.at = Some(now);
                }
                (m.cpu_pct, m.rx_bps, m.tx_bps)
            };

            let (mem_total, mem_avail) = core::read_mem().unwrap_or((0, 0));
            let (disk_used, disk_total) = core::disk_usage("/").unwrap_or((0, 0));
            let (l1, l5, l15) = core::read_loadavg().unwrap_or((0.0, 0.0, 0.0));
            let body = serde_json::json!({
                "cpu_pct": cpu_pct,
                "cores": core::cpu_count(),
                "mem_total_kb": mem_total,
                "mem_avail_kb": mem_avail,
                "disk_total_kb": disk_total,
                "disk_used_kb": disk_used,
                "load1": l1,
                "load5": l5,
                "load15": l15,
                "uptime_secs": core::read_uptime_secs().unwrap_or(0.0),
                "rx_bps": rx_bps,
                "tx_bps": tx_bps,
                "panel_rss_kb": core::read_self_rss_kb().unwrap_or(0),
            });
            send_json(req, 200, body);
        }
        (Method::Get, "/api/scan") => {
            let mut items: Vec<(u16, String, String)> = Vec::new();
            if let Ok(out) = std::process::Command::new("ss").args(["-tlnpH"]).output() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() < 4 {
                        continue;
                    }
                    let local = cols[3];
                    let Some((addr, port_s)) = local.rsplit_once(':') else {
                        continue;
                    };
                    let Ok(port) = port_s.parse::<u16>() else {
                        continue;
                    };
                    if port == 0 {
                        continue;
                    }
                    let process = line
                        .split("users:((")
                        .nth(1)
                        .and_then(|s| s.split('"').nth(1))
                        .unwrap_or("")
                        .to_string();
                    let addr = addr.trim_start_matches('[').trim_end_matches(']').to_string();
                    if items
                        .iter()
                        .any(|(p, a, n)| *p == port && *a == addr && *n == process)
                    {
                        continue;
                    }
                    items.push((port, addr, process));
                }
            }
            // 已经加进规则的端口不再列出, 免得重复添加
            let used: Vec<u16> = st
                .tunnel
                .lock()
                .unwrap()
                .rules
                .iter()
                .filter_map(|r| r.port())
                .collect();
            items.retain(|(p, _, _)| !used.contains(p));
            items.sort_by_key(|(p, _, _)| *p);
            let services: Vec<serde_json::Value> = items
                .iter()
                .map(|(p, a, n)| serde_json::json!({"port": p, "addr": a, "process": n}))
                .collect();
            send_json(req, 200, serde_json::json!({"services": services}));
        }
        _ => send_json(req, 404, serde_json::json!({"error": "not found"})),
    }
}

// ------------------------------------------------------------------ 启动

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg_path = config_path();
    let mut cfg = load_config(&cfg_path).unwrap_or_default();

    let mut dirty = false;
    if cfg.access_token.is_empty() {
        cfg.access_token = rand_hex(24);
        dirty = true;
    }
    if dirty {
        if let Err(e) = save_config(&cfg_path, &cfg) {
            eprintln!("写入配置失败: {e}");
        }
    }

    if args.iter().any(|a| a == "--selftest") {
        println!("config 路径: {}", cfg_path.display());
        println!("password_hash 长度: {}", cfg.password_hash.len());
        println!("access_token 长度: {}", cfg.access_token.len());
        if let Ok(pw) = std::env::var("PANEL_PASSWORD") {
            println!("口令校验(PANEL_PASSWORD): {}", verify_password(&cfg.password_hash, &pw));
        }
        if let Ok(tk) = std::env::var("PANEL_TOKEN") {
            println!("令牌比较(PANEL_TOKEN): {}", ct_eq(&tk, &cfg.access_token));
        }
        return;
    }

    if args.iter().any(|a| a == "--print-token") {
        println!("{}", cfg.access_token);
        return;
    }

    if args.iter().any(|a| a == "--set-password") {
        let pw = std::env::var("PANEL_PASSWORD").unwrap_or_default();
        if pw.chars().count() < 8 {
            eprintln!("口令至少 8 位; 用法: PANEL_PASSWORD='你的口令' cf-tunnel-server --set-password");
            std::process::exit(2);
        }
        match hash_password(&pw) {
            Ok(h) => {
                cfg.password_hash = h;
                match save_config(&cfg_path, &cfg) {
                    Ok(()) => {
                        println!("口令已更新: {}", cfg_path.display());
                        println!("访问令牌可随时用 --print-token 查看");
                        let sp = sessions_path();
                        if sp.exists() {
                            let _ = std::fs::remove_file(&sp);
                            println!("已清空所有登录会话（{}）", sp.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("保存失败: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("生成哈希失败: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let mut bind = cfg.bind.clone();
    let mut port = cfg.port;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" if i + 1 < args.len() => {
                bind = args[i + 1].clone();
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(port);
                i += 2;
            }
            _ => i += 1,
        }
    }

    if cfg.password_hash.is_empty() {
        eprintln!("还没有设置口令, 先执行:");
        eprintln!("  PANEL_PASSWORD='你的口令' {} --set-password", args[0]);
        std::process::exit(2);
    }

    let cf = core::find_cloudflared();
    if cf.is_none() {
        eprintln!("警告: 没找到 cloudflared, 面板能打开但无法启动隧道");
    }
    let tunnel_path = std::env::var("TUNNEL_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| core::cf_dir().join("agent2api-pc.yml"));
    let mut tunnel = core::read_config(&tunnel_path).unwrap_or_default();
    let sidecar = core::rules_sidecar(&tunnel_path);
    match core::read_rules_sidecar(&sidecar) {
        Some(rules) => {
            tunnel.rules = rules;
        }
        None => {
            if !tunnel.rules.is_empty() {
                let _ = core::write_rules_sidecar(&sidecar, &tunnel.rules);
            }
        }
    }

    let st = Arc::new(State {
        cfg: Mutex::new(cfg.clone()),
        sessions: Mutex::new(load_sessions_from(&sessions_path(), ttl_secs_from(&cfg))),
        metrics: Mutex::new(MetricsPrev::default()),
        fails: Mutex::new(HashMap::new()),
        runner: Mutex::new(core::TunnelRunner::new()),
        tunnel: Mutex::new(tunnel),
        logs: Mutex::new(Vec::new()),
        cf,
        conn: Mutex::new(String::new()),
    });

    // 按上次状态恢复隧道（面板重启或机器重启后自动拉起）
    if core::read_run_state(&run_state_path()) {
        let tcfg = st.tunnel.lock().unwrap().clone();
        let can = st.cf.is_some() && !tcfg.rules.is_empty() && !core::external_running();
        if can {
            let cf = st.cf.clone().unwrap();
            let mut runner = st.runner.lock().unwrap();
            match spawn_tunnel(&mut runner, &cf, &tcfg) {
                Ok(()) => st.log("已按上次状态自动启动隧道"),
                Err(e) => st.log(format!("自动启动隧道失败: {e}")),
            }
        } else {
            st.log("上次为运行状态，但缺少 cloudflared / 规则 / 已有外部进程，跳过自动启动");
        }
    }

    // 日志搬运: cloudflared 输出 -> 面板日志缓冲
    {
        let st2 = st.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            let lines = st2.runner.lock().unwrap().drain_logs();
            for l in lines {
                st2.log(l);
            }
        });
    }

    // 连接状态缓存: tunnel info 要走网络, 不能每次请求都算
    {
        let st3 = st.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let running = st3.runner.lock().unwrap().running();
            if !running {
                st3.conn.lock().unwrap().clear();
                continue;
            }
            let (cf, name) = match (&st3.cf, st3.tunnel.lock().unwrap().tunnel.clone()) {
                (Some(cf), name) if !name.is_empty() => (cf.clone(), name),
                _ => continue,
            };
            let text = core::tunnel_connections(&cf, &name);
            *st3.conn.lock().unwrap() = text;
        });
    }

    // 配置监视: panel.json 被改过（例如 --set-password）就重新载入, 并作废旧会话
    {
        let st4 = st.clone();
        let watched = cfg_path.clone();
        std::thread::spawn(move || {
            let mut last = std::fs::metadata(&watched).and_then(|m| m.modified()).ok();
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let now = std::fs::metadata(&watched).and_then(|m| m.modified()).ok();
                if now.is_none() || now == last {
                    continue;
                }
                last = now;
                let Ok(text) = std::fs::read_to_string(&watched) else {
                    continue;
                };
                let Ok(fresh) = serde_json::from_str::<PanelConfig>(&text) else {
                    continue;
                };
                let new_fp = pw_fingerprint(&fresh.password_hash);
                *st4.cfg.lock().unwrap() = fresh;
                let dropped = {
                    let mut sessions = st4.sessions.lock().unwrap();
                    let before = sessions.len();
                    sessions.retain(|_, s| s.pw_fp == new_fp);
                    before - sessions.len()
                };
                st4.persist_sessions();
                if dropped > 0 {
                    st4.log(format!("配置已变更, 作废 {dropped} 个登录会话"));
                } else {
                    st4.log("配置已变更, 已重新载入");
                }
            }
        });
    }

    let addr = format!("{bind}:{port}");
    let server = match Server::http(&addr) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("监听 {addr} 失败: {e}");
            std::process::exit(1);
        }
    };
    st.log(format!("面板已启动 http://{addr}"));
    println!("内网穿透面板已启动: http://{addr}");
    println!("配置文件: {}", cfg_path.display());
    if cfg.bind == "127.0.0.1" {
        println!("当前只监听本机; 对外请用 nginx 反代并加 limit_req 限速");
    }

    let mut workers = Vec::new();
    for _ in 0..8 {
        let server = server.clone();
        let st = st.clone();
        workers.push(std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(&st, req);
            }
        }));
    }
    for w in workers {
        let _ = w.join();
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cftp-{}-{}.json", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn long_ttl_keeps_idle_sessions_short_ttl_does_not() {
        let p = tmp("ttl");
        let mut m = HashMap::new();
        m.insert(
            "sid_idle".to_string(),
            Session {
                csrf: "c".to_string(),
                last: now_unix().saturating_sub(7200),
                pw_fp: "fp".to_string(),
            },
        );
        save_sessions_to(&p, &m);
        assert_eq!(load_sessions_from(&p, 1800).len(), 0, "短 TTL 应丢弃闲置会话");
        assert_eq!(load_sessions_from(&p, 604800).len(), 1, "长 TTL 应保留闲置会话");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn pw_fingerprint_changes_with_hash() {
        // 真实场景: 同一个口令重新设置, 盐和摘要都会变
        let a = "$argon2id$v=19$m=19456,t=2,p=1$U0FMVA$GBsddhMdnTUKhQPx4tQewMQS+uougMRZhi2DAbeVY30";
        let b = "$argon2id$v=19$m=19456,t=2,p=1$U0FMVEI$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(pw_fingerprint(a), pw_fingerprint(a), "同一哈希指纹必须稳定");
        assert_ne!(
            pw_fingerprint(a),
            pw_fingerprint(b),
            "口令重新设置后指纹必须变化, 否则旧会话不会失效"
        );
        assert_eq!(pw_fingerprint(a).len(), 16);
        // 空哈希不能 panic, 也不能凭空造出非空指纹
        assert_eq!(pw_fingerprint("").len(), 0);
    }

    #[test]
    fn sessions_survive_restart_but_expired_ones_do_not() {
        let p = tmp("sess");
        let mut m = HashMap::new();
        m.insert(
            "sid_live".to_string(),
            Session { csrf: "csrf-live".to_string(), last: now_unix(), pw_fp: "fp-a".to_string() },
        );
        m.insert(
            "sid_stale".to_string(),
            Session { csrf: "csrf-stale".to_string(), last: now_unix().saturating_sub(7200), pw_fp: "fp-a".to_string() },
        );
        save_sessions_to(&p, &m);

        // 30 分钟 TTL: 刚建的必须活下来(重启不掉登录态), 2 小时前的必须被丢弃
        let loaded = load_sessions_from(&p, 1800);
        assert_eq!(loaded.len(), 1, "只应恢复未过期会话");
        assert_eq!(loaded.get("sid_live").map(|s| s.csrf.as_str()), Some("csrf-live"));
        assert!(loaded.get("sid_stale").is_none(), "过期会话不许恢复");
        assert_eq!(
            loaded.get("sid_live").map(|s| s.pw_fp.as_str()),
            Some("fp-a"),
            "口令指纹必须一起持久化, 否则改口令后旧会话不会失效"
        );

        // 文件缺失/损坏都必须当成空表, 不许 panic
        let _ = std::fs::remove_file(&p);
        assert!(load_sessions_from(&p, 1800).is_empty());
        std::fs::write(&p, "(not json").unwrap();
        assert!(load_sessions_from(&p, 1800).is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
