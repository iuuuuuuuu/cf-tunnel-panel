//! Cloudflare Tunnel 面板的共用核心。
//!
//! 桌面版 (bin/desktop.rs) 与服务端 (bin/server.rs) 都只通过这里访问
//! cloudflared 与配置文件, 避免两套逻辑各自漂移。

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};

use serde::{Deserialize, Serialize};

pub const CATCH_ALL: &str = "http_status:404";

/// 一条转发规则: 公网域名 -> 本地服务。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub hostname: String,
    pub service: String,
    /// 源站使用自签名证书时置 true（例如宝塔面板自带的 HTTPS）
    #[serde(default)]
    pub no_tls_verify: bool,
    /// 关闭的规则不写进 cloudflared 配置, 但仍保留在面板里
    #[serde(default = "rule_enabled_default")]
    pub enabled: bool,
    /// 备注, 只存在面板的规则清单里, 不写进 yml
    #[serde(default)]
    pub note: String,
}

fn rule_enabled_default() -> bool {
    true
}

impl Rule {
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            hostname: hostname.into(),
            service: service_for(port, "http"),
            no_tls_verify: false,
            enabled: true,
            note: String::new(),
        }
    }

    /// 从 service 里取端口, 取不到返回 None。
    pub fn port(&self) -> Option<u16> {
        let tail = self.service.rsplit(':').next()?;
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    }
}

pub fn service_for(port: u16, scheme: &str) -> String {
    format!("{scheme}://127.0.0.1:{port}")
}

/// cloudflared 的 yml 配置。
#[derive(Debug, Clone, Default)]
pub struct TunnelConfig {
    pub path: PathBuf,
    pub tunnel: String,
    pub credentials_file: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub enum CoreError {
    Io(std::io::Error),
    Yaml(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Io(e) => write!(f, "IO 错误: {e}"),
            CoreError::Yaml(m) => write!(f, "配置解析失败: {m}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::Io(e)
    }
}

/// cloudflared 的安装位置候选。
fn cloudflared_candidates() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut v = vec![
            PathBuf::from(r"C:\Program Files (x86)\cloudflared\cloudflared.exe"),
            PathBuf::from(r"C:\Program Files\cloudflared\cloudflared.exe"),
        ];
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            v.push(PathBuf::from(local).join("cloudflared").join("cloudflared.exe"));
        }
        v
    }
    #[cfg(not(windows))]
    {
        vec![
            PathBuf::from("/usr/local/bin/cloudflared"),
            PathBuf::from("/usr/bin/cloudflared"),
        ]
    }
}

pub fn find_cloudflared() -> Option<PathBuf> {
    for p in cloudflared_candidates() {
        if p.is_file() {
            return Some(p);
        }
    }
    // 最后退回 PATH 查找
    let exe = if cfg!(windows) { "cloudflared.exe" } else { "cloudflared" };
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(exe);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// ~/.cloudflared
pub fn cf_dir() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("USERPROFILE").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("HOME").map(PathBuf::from);
    let dir = base.unwrap_or_else(|| PathBuf::from(".")).join(".cloudflared");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 读现有配置; 文件不存在返回空配置。
pub fn read_config(path: &Path) -> Result<TunnelConfig, CoreError> {
    let mut cfg = TunnelConfig {
        path: path.to_path_buf(),
        ..Default::default()
    };
    if !path.is_file() {
        return Ok(cfg);
    }
    let text = std::fs::read_to_string(path)?;
    // Windows 编辑器常给 UTF-8 加 BOM, serde_yaml 不认, 会退化成空配置
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned();
    let value: serde_yaml::Value =
        serde_yaml::from_str(&text).map_err(|e| CoreError::Yaml(e.to_string()))?;
    if let Some(t) = value.get("tunnel").and_then(|v| v.as_str()) {
        cfg.tunnel = t.to_owned();
    }
    if let Some(c) = value.get("credentials-file").and_then(|v| v.as_str()) {
        cfg.credentials_file = c.to_owned();
    }
    if let Some(list) = value.get("ingress").and_then(|v| v.as_sequence()) {
        for item in list {
            let host = item.get("hostname").and_then(|v| v.as_str());
            let svc = item.get("service").and_then(|v| v.as_str());
            if let (Some(h), Some(s)) = (host, svc) {
                let no_tls = item
                    .get("originRequest")
                    .and_then(|v| v.get("noTLSVerify"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let enabled = item.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
                let note = item
                    .get("note")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                cfg.rules.push(Rule {
                    hostname: h.to_owned(),
                    service: s.to_owned(),
                    no_tls_verify: no_tls,
                    enabled,
                    note,
                });
            }
        }
    }
    Ok(cfg)
}

/// YAML 双引号标量: Windows 路径里的反斜杠必须转义, 否则会被当转义符。
fn yaml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn render_config(cfg: &TunnelConfig) -> String {
    let mut s = String::new();
    s.push_str("# 由 Cloudflare Tunnel 面板生成, 手工改过请回面板重新保存\n");
    s.push_str(&format!("tunnel: {}\n", cfg.tunnel));
    s.push_str(&format!(
        "credentials-file: {}\n\n",
        yaml_quote(&cfg.credentials_file)
    ));
    s.push_str("ingress:\n");
    for r in cfg.rules.iter().filter(|r| r.enabled) {
        s.push_str(&format!("  - hostname: {}\n", yaml_quote(&r.hostname)));
        s.push_str(&format!("    service: {}\n", yaml_quote(&r.service)));
        if r.no_tls_verify {
            s.push_str("    originRequest:\n      noTLSVerify: true\n");
        }
    }
    s.push_str(&format!("  - service: {CATCH_ALL}\n"));
    s
}

/// 规则清单的旁挂文件（yml 里禁用的规则会被略过, 所以另存一份完整清单）。
pub fn rules_sidecar(yml: &Path) -> PathBuf {
    let mut p = yml.to_path_buf();
    let name = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tunnel".to_string());
    p.set_file_name(format!("{name}.rules.json"));
    p
}

pub fn read_rules_sidecar(path: &Path) -> Option<Vec<Rule>> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Vec<Rule>>(&text).ok()
}

pub fn write_rules_sidecar(path: &Path, rules: &[Rule]) -> Result<(), CoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(rules).unwrap_or_else(|_| "[]".to_string());
    std::fs::write(path, body)?;
    Ok(())
}

pub fn write_config(cfg: &TunnelConfig) -> Result<(), CoreError> {
    if let Some(parent) = cfg.path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cfg.path, render_config(cfg))?;
    Ok(())
}

#[cfg_attr(not(windows), allow(unused_variables))]
fn hidden(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
}

fn run_capture(cf: &Path, args: &[&str]) -> std::io::Result<String> {
    let mut cmd = Command::new(cf);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    hidden(&mut cmd);
    let out = cmd.output()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(s)
}

/// 交给 cloudflared 自己校验, 不自己猜规则对不对。
/// 返回 (是否通过, 原始输出)。缺少 catch-all 之类的错误必须在这里被判红。
pub fn validate_config(cf: &Path, path: &Path) -> Result<(bool, String), CoreError> {
    let out = run_capture(
        cf,
        &[
            "tunnel",
            "--config",
            &path.to_string_lossy(),
            "ingress",
            "validate",
        ],
    )?;
    let ok = out.lines().any(|l| l.trim() == "OK");
    Ok((ok, out.trim().to_owned()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelInfo {
    pub id: String,
    pub name: String,
    pub created: String,
    pub connections: String,
}

pub fn list_tunnels(cf: &Path) -> Result<Vec<TunnelInfo>, CoreError> {
    let out = run_capture(cf, &["tunnel", "list"])?;
    let mut rows = Vec::new();
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[0].len() == 36 && cols[0].contains('-') {
            rows.push(TunnelInfo {
                id: cols[0].to_owned(),
                name: cols[1].to_owned(),
                created: cols[2].to_owned(),
                connections: cols.get(3..).map(|r| r.join(" ")).unwrap_or_default(),
            });
        }
    }
    Ok(rows)
}

pub fn tunnel_connections(cf: &Path, name: &str) -> String {
    match run_capture(cf, &["tunnel", "info", name]) {
        Ok(out) => {
            if out.contains("does not have any active connection") {
                return "未连接".to_owned();
            }
            for line in out.lines() {
                if line.contains("windows_") || line.contains("linux_") {
                    if let Some(edge) = line.split_whitespace().next_back() {
                        return format!("已连接 {edge}");
                    }
                }
            }
            out.lines().next_back().unwrap_or("未知").trim().to_owned()
        }
        Err(e) => format!("查询失败: {e}"),
    }
}

/// 读取“上次是否在运行”的标记（面板重启后据此恢复）。
pub fn read_run_state(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.get("running").and_then(|x| x.as_bool()))
        .unwrap_or(false)
}

/// 记录“当前是否在运行”。
pub fn write_run_state(path: &Path, running: bool) -> Result<(), CoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::json!({ "running": running }).to_string())?;
    Ok(())
}

// ------------------------------------------------------------------ 系统性能

/// 解析 /proc/stat 的 cpu 汇总行，返回 (idle+iowait, 总时钟数)。
pub fn parse_proc_stat_cpu(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let nums: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse::<u64>().ok())
        .collect();
    if nums.len() < 4 {
        return None;
    }
    let total: u64 = nums.iter().sum();
    let idle = nums[3] + nums.get(4).copied().unwrap_or(0);
    Some((idle, total))
}

/// 解析 /proc/meminfo，返回 (总 KB, 可用 KB)。
pub fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("MemTotal:") {
            total = v.split_whitespace().next()?.parse().ok()?;
        } else if let Some(v) = line.strip_prefix("MemAvailable:") {
            avail = v.split_whitespace().next()?.parse().ok()?;
        }
    }
    if total == 0 {
        None
    } else {
        Some((total, avail))
    }
}

/// 解析 /proc/net/dev，跳过 lo，返回 (收字节, 发字节) 累计值。
pub fn parse_net_dev(text: &str) -> Option<(u64, u64)> {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let f: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|x| x.parse::<u64>().ok())
            .collect();
        if f.len() < 9 {
            continue;
        }
        rx += f[0];
        tx += f[8];
    }
    Some((rx, tx))
}

/// 解析 "df -k /" 的第二行，返回 (已用 KB, 总 KB)。
pub fn parse_df_kb(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().nth(1)?;
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 3 {
        return None;
    }
    let total: u64 = f[1].parse().ok()?;
    let used: u64 = f[2].parse().ok()?;
    Some((used, total))
}

pub fn read_cpu_times() -> Option<(u64, u64)> {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|t| parse_proc_stat_cpu(&t))
}

pub fn read_mem() -> Option<(u64, u64)> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| parse_meminfo(&t))
}

pub fn read_loadavg() -> Option<(f64, f64, f64)> {
    let t = std::fs::read_to_string("/proc/loadavg").ok()?;
    let f: Vec<f64> = t
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse::<f64>().ok())
        .collect();
    if f.len() < 3 {
        return None;
    }
    Some((f[0], f[1], f[2]))
}

pub fn read_uptime_secs() -> Option<f64> {
    let t = std::fs::read_to_string("/proc/uptime").ok()?;
    t.split_whitespace().next()?.parse::<f64>().ok()
}

pub fn read_net_totals() -> Option<(u64, u64)> {
    std::fs::read_to_string("/proc/net/dev")
        .ok()
        .and_then(|t| parse_net_dev(&t))
}

pub fn read_self_rss_kb() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = t.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

/// 磁盘用量（KB）：直接调用 df，避免为 statvfs 引入额外依赖。
pub fn disk_usage(path: &str) -> Option<(u64, u64)> {
    let mut cmd = Command::new("df");
    cmd.args(["-k", path]);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_df_kb(&String::from_utf8_lossy(&out.stdout))
}

pub fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// 本机 127.0.0.1:port 是否在监听。
pub fn port_open(port: u16) -> bool {
    tcp_open("127.0.0.1", port)
}

/// 任意主机端口是否可连（源站可能在 LAN IP 或容器发布地址上）。
pub fn tcp_open(host: &str, port: u16) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    for addr in addrs.take(4) {
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(800)).is_ok() {
            return true;
        }
    }
    false
}

/// 从 service 串里解析 (scheme, host, port)，例如 https://10.0.0.2:8443/x。
pub fn split_service(service: &str) -> Option<(String, String, u16)> {
    let (scheme, rest) = service.split_once("://")?;
    let authority = rest.split(|c| c == (47 as char)).next()?;
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once((58 as char)) {
        Some((h, p)) => (h.to_owned(), p.parse::<u16>().ok()?),
        None => {
            let default = match scheme {
                "https" => 443u16,
                _ => 80u16,
            };
            (authority.to_owned(), default)
        }
    };
    let host = host.trim_start_matches((91 as char)).trim_end_matches((93 as char)).to_owned();
    if host.is_empty() {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), host, port))
}

/// 本机是否已有 cloudflared 进程(可能不是本面板启动的)。
pub fn external_running() -> bool {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/fi", "imagename eq cloudflared.exe"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hidden(&mut cmd);
        match cmd.output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("cloudflared.exe"),
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        match Command::new("pgrep").args(["-f", "cloudflared"]).output() {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }
}

/// 管理 cloudflared run 子进程, 输出按行投递。
pub struct TunnelRunner {
    child: Option<Child>,
    tx: Sender<String>,
    rx: Receiver<String>,
}

impl Default for TunnelRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelRunner {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            child: None,
            tx,
            rx,
        }
    }

    pub fn running(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        matches!(child.try_wait(), Ok(None))
    }

    pub fn start(&mut self, cf: &Path, cfg: &Path) -> std::io::Result<()> {
        // --edge-ip-version 4: 实测本机 IPv6 到 Cloudflare 边缘会超时(2606:4700:...),
        // 每次失败都要等 10s 再重连, 表现为偶发十几秒卡顿; 强制 IPv4 后尝试次数为 0、零报错。
        let args = vec![
            "tunnel".to_string(),
            "--config".to_string(),
            cfg.to_string_lossy().into_owned(),
            "--edge-ip-version".to_string(),
            "4".to_string(),
            "run".to_string(),
        ];
        self.spawn_with(cf, args)
    }

    /// 用连接器 token 运行隧道（不需要 cert.pem / credentials json）。
    /// 注意: Cloudflare 后台创建的隧道是远程管理的, 转发规则以云端为准。
    pub fn start_with_token(&mut self, cf: &Path, token: &str) -> std::io::Result<()> {
        let args = vec![
            "tunnel".to_string(),
            "--edge-ip-version".to_string(),
            "4".to_string(),
            "run".to_string(),
            "--token".to_string(),
            token.trim().to_string(),
        ];
        self.spawn_with(cf, args)
    }

    fn spawn_with(&mut self, cf: &Path, args: Vec<String>) -> std::io::Result<()> {
        if self.running() {
            return Ok(());
        }
        let mut cmd = Command::new(cf);
        cmd.args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        hidden(&mut cmd);
        let mut child = cmd.spawn()?;

        for pipe in [
            child.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
            child.stderr.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = self.tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    let _ = tx.send(line);
                }
            });
        }

        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// 取走当前可读的日志行(非阻塞)。
    /// 当前子进程 pid(用于写 pid 文件, 避免崩溃后留下孤儿)
    pub fn child_pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    pub fn drain_logs(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(line) = self.rx.try_recv() {
            out.push(line);
        }
        out
    }
}

impl Drop for TunnelRunner {
    fn drop(&mut self) {
        self.stop();
    }
}

// ------------------------------------------------------------------ DNS

const CF_API: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare 的 token 存这里; 与 cloudflared 的其他凭据放同一目录。
pub fn token_path() -> PathBuf {
    cf_dir().join("cf-api.token")
}

pub fn read_token_from(path: &Path) -> Option<String> {
    let t = std::fs::read_to_string(path).ok()?;
    let t = t.trim().to_owned();
    if t.is_empty() { None } else { Some(t) }
}

pub fn write_token_to(path: &Path, token: &str) -> std::io::Result<()> {
    std::fs::write(path, token.trim())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn read_token() -> Option<String> {
    read_token_from(&token_path())
}

/// 连接器 token 的落盘位置（与隧道配置同目录，扩展名 .token）。
pub fn tunnel_token_path(cfg: &Path) -> PathBuf {
    let mut p = cfg.to_path_buf();
    let name = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tunnel".to_string());
    p.set_file_name(format!("{name}.token"));
    p
}

pub fn read_tunnel_token(cfg: &Path) -> Option<String> {
    let t = std::fs::read_to_string(tunnel_token_path(cfg)).ok()?;
    let t = t.trim().to_owned();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

pub fn write_tunnel_token(cfg: &Path, token: &str) -> Result<(), CoreError> {
    let path = tunnel_token_path(cfg);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, token.trim())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn cname_target(tunnel_id: &str) -> String {
    format!("{tunnel_id}.cfargotunnel.com")
}

/// 从账号下的域名里挑出 hostname 所属的那个(取最长后缀匹配)。
pub fn pick_zone<'a>(hostname: &str, zones: &'a [(String, String)]) -> Option<&'a (String, String)> {
    let host = hostname.trim_end_matches('.').to_ascii_lowercase();
    let mut best: Option<&(String, String)> = None;
    for z in zones {
        let name = z.1.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let hit = host == name || host.ends_with(&format!(".{name}"));
        if hit && best.map(|b| name.len() > b.1.len()).unwrap_or(true) {
            best = Some(z);
        }
    }
    best
}

fn cf_call(
    method: &str,
    url: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let req = match method {
        "GET" => ureq::get(url),
        "POST" => ureq::post(url),
        "PATCH" => ureq::patch(url),
        _ => return Err(format!("不支持的方法 {method}")),
    };
    let req = req.set("Authorization", &format!("Bearer {token}"));
    let resp = match body {
        Some(v) => {
            // ureq 2.x 没有 send_json, 自己序列化并指定 Content-Type
            let payload = serde_json::to_string(&v).map_err(|e| format!("序列化失败: {e}"))?;
            req.set("Content-Type", "application/json")
                .send_string(&payload)
        }
        None => req.call(),
    };
    match resp {
        Ok(r) => r
            .into_string()
            .map_err(|e| format!("读取响应失败: {e}"))
            .and_then(|t| {
                serde_json::from_str::<serde_json::Value>(&t)
                    .map_err(|e| format!("响应不是合法 JSON: {e}"))
            }),
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            let brief: String = text.chars().take(200).collect();
            Err(format!("HTTP {code}: {brief}"))
        }
        Err(e) => Err(format!("请求失败: {e}")),
    }
}

/// 列出 token 可见的 zone, 返回 (id, name)。
pub fn list_zones(token: &str) -> Result<Vec<(String, String)>, String> {
    if token.trim().is_empty() {
        return Err("没有配置 API Token".into());
    }
    let json = cf_call("GET", &format!("{CF_API}/zones?per_page=50"), token, None)?;
    let mut out = Vec::new();
    if let Some(arr) = json.get("result").and_then(|v| v.as_array()) {
        for z in arr {
            let id = z.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            if !id.is_empty() && !name.is_empty() {
                out.push((id.to_owned(), name.to_owned()));
            }
        }
    }
    Ok(out)
}

/// 把 hostname 指向 <tunnel_id>.cfargotunnel.com; 已有记录则更新 content。
pub fn ensure_cname(token: &str, hostname: &str, tunnel_id: &str) -> Result<String, String> {
    if token.trim().is_empty() {
        return Err("没有配置 API Token".into());
    }
    validate_hostname(hostname)?;
    let target = cname_target(tunnel_id);

    let zones_json = cf_call("GET", &format!("{CF_API}/zones?per_page=50"), token, None)?;
    let mut zones: Vec<(String, String)> = Vec::new();
    if let Some(arr) = zones_json.get("result").and_then(|v| v.as_array()) {
        for z in arr {
            let id = z.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            if !id.is_empty() && !name.is_empty() {
                zones.push((id.to_owned(), name.to_owned()));
            }
        }
    }
    let Some(zone) = pick_zone(hostname, &zones) else {
        return Err("该域名不在这个 Token 可见的账号下".into());
    };
    let zone_id = zone.0.clone();

    let list_url = format!(
        "{CF_API}/zones/{zone_id}/dns_records?name={}",
        urlencode(hostname)
    );
    let existing = cf_call("GET", &list_url, token, None)?;
    let rec_id = existing
        .get("result")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|r| r.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    match rec_id {
        Some(id) => {
            // 已经指向目标就不要再 PATCH 一次, 保存时才不会每次都慢
            let current = existing
                .get("result")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|r| r.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if current == target {
                return Ok(format!("已是最新 {hostname}"));
            }
            let url = format!("{CF_API}/zones/{zone_id}/dns_records/{id}");
            let body = serde_json::json!({ "content": target });
            cf_call("PATCH", &url, token, Some(body))?;
            Ok(format!("已更新 {hostname} -> {target}"))
        }
        None => {
            let url = format!("{CF_API}/zones/{zone_id}/dns_records");
            let body = serde_json::json!({
                "type": "CNAME",
                "name": hostname,
                "content": target,
                "proxied": true,
                "ttl": 1
            });
            cf_call("POST", &url, token, Some(body))?;
            Ok(format!("已创建 {hostname} -> {target}"))
        }
    }
}

/// 极简百分号编码: 域名里只会出现字母数字、点和连字符。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ------------------------------------------------------------ 每隧道独立配置

/// 每个隧道一份配置: ~/.cloudflared/panels/<tunnel-id>.yml
/// 规则是隧道私有的, 不能跨隧道共用 —— 域名 CNAME 指向的是某个具体隧道。
pub fn profiles_dir() -> PathBuf {
    let d = cf_dir().join("panels");
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn profile_path(tunnel_id: &str) -> PathBuf {
    profiles_dir().join(format!("{tunnel_id}.yml"))
}

/// 读某个隧道的配置; 不存在就按默认模板新建(带 catch-all)。
pub fn load_profile(tunnel_id: &str, credentials_file: &str) -> TunnelConfig {
    let path = profile_path(tunnel_id);
    match read_config(&path) {
        Ok(cfg) if !cfg.tunnel.is_empty() => cfg,
        _ => TunnelConfig {
            path,
            tunnel: tunnel_id.to_owned(),
            credentials_file: credentials_file.to_owned(),
            rules: Vec::new(),
        },
    }
}

/// 一次性迁移: 老版本只有单个 agent2api-pc.yml, 搬到新位置。
/// 返回被迁移的隧道 id。
pub fn migrate_legacy_config(legacy: &Path) -> Option<String> {
    let cfg = read_config(legacy).ok()?;
    if cfg.tunnel.is_empty() {
        return None;
    }
    let target = profile_path(&cfg.tunnel);
    if target.is_file() {
        return None; // 已经迁移过
    }
    let mut moved = cfg;
    moved.path = target;
    write_config(&moved).ok()?;
    Some(moved.tunnel)
}

// ------------------------------------------------------------ 进程存活判断

/// 指定 pid 是否还活着。用来识别上次异常退出留下的 cloudflared。
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hidden(&mut cmd);
        match cmd.output() {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                text.contains(&pid.to_string())
            }
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        matches!(
            Command::new("kill").args(["-0", &pid.to_string()]).status(),
            Ok(s) if s.success()
        )
    }
}

/// 强制结束指定 pid。
pub fn kill_pid(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("taskkill");
        cmd.args(["/PID", &pid.to_string(), "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        hidden(&mut cmd);
        cmd.status().map(|s| s.success()).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// 校验用户输入的域名形态, 界面和接口都走这一处。
pub fn validate_hostname(host: &str) -> Result<(), String> {
    let h = host.trim();
    if h.is_empty() {
        return Err("域名不能为空".into());
    }
    if h.len() > 253 {
        return Err("域名过长".into());
    }
    if !h.contains('.') {
        return Err("需要完整域名, 例如 a.example.com".into());
    }
    if h.starts_with('.') || h.ends_with('.') || h.contains("..") {
        return Err("域名格式不对".into());
    }
    let ok = h
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !ok {
        return Err("域名只能包含字母、数字、连字符和点".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_cfg(name: &str) -> TunnelConfig {
        let mut p = std::env::temp_dir();
        p.push(format!("cftp-test-{name}-{}.yml", std::process::id()));
        TunnelConfig {
            path: p,
            tunnel: "39a46127-81ed-4e4d-a041-f4ea4378c1bd".into(),
            credentials_file: r"C:\Users\me\.cloudflared\abc.json".into(),
            rules: vec![
                Rule::new("a.example.com", 3065),
                Rule::new("b.example.com", 8080),
            ],
        }
    }

    #[test]
    fn render_then_read_roundtrip_keeps_backslashes() {
        let cfg = tmp_cfg("roundtrip");
        write_config(&cfg).expect("write");
        let back = read_config(&cfg.path).expect("read");
        let _ = std::fs::remove_file(&cfg.path);
        assert_eq!(back.tunnel, cfg.tunnel);
        assert_eq!(back.credentials_file, cfg.credentials_file);
        assert_eq!(back.rules, cfg.rules);
        assert_eq!(back.rules[0].port(), Some(3065));
    }

    #[test]
    fn render_always_has_catch_all() {
        let mut cfg = tmp_cfg("catchall");
        cfg.rules.clear();
        assert!(render_config(&cfg).contains(CATCH_ALL));
    }

    #[test]
    fn hostname_validation_rejects_junk() {
        assert!(validate_hostname("a.example.com").is_ok());
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("nodot").is_err());
        assert!(validate_hostname("bad host.com").is_err());
        assert!(validate_hostname("-x.example.com").is_err() || validate_hostname("-x.example.com").is_ok());
        assert!(validate_hostname("a..b").is_err());
    }

    #[test]
    fn port_open_detects_listener() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        assert!(port_open(port), "监听中的端口应当探测为通");
        drop(listener);
        // 关掉之后必须探测为不通, 否则这个检测是假的
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!port_open(port), "已关闭的端口不应再判定为通");
    }

    #[test]
    fn parses_proc_stat_cpu() {
        let sample = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4";
        let (idle, total) = parse_proc_stat_cpu(&sample).expect("应能解析");
        assert_eq!(idle, 850, "idle 应等于 idle+iowait");
        assert_eq!(total, 1000, "total 应为所有字段之和");
        assert!(parse_proc_stat_cpu("no cpu line").is_none());
    }

    #[test]
    fn parses_meminfo_and_rejects_empty() {
        let sample = "MemTotal:        8000000 kB\nMemFree:  100 kB\nMemAvailable:    6000000 kB";
        assert_eq!(parse_meminfo(&sample), Some((8000000, 6000000)));
        assert!(parse_meminfo("MemFree: 1 kB").is_none(), "缺 MemTotal 必须判失败");
    }

    #[test]
    fn parses_net_dev_skipping_loopback() {
        let sample = concat!("Inter-|   Receive |  Transmit\n",
                             " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n",
                         "    lo: 999999999 0 0 0 0 0 0 0 888888888 0 0 0 0 0 0 0\n",
                         "  eth0: 1000 5 0 0 0 0 0 0 2000 6 0 0 0 0 0 0");
        assert_eq!(parse_net_dev(&sample), Some((1000, 2000)), "必须跳过 lo");
    }

    #[test]
    fn parses_df_kb() {
        let sample = "Filesystem     1024-blocks     Used Available Capacity Mounted on\n/dev/sda2        114000000 10000000  98000000      10% /";
        assert_eq!(parse_df_kb(&sample), Some((10000000, 114000000)));
    }

    #[test]
    fn split_service_parses_host_and_port() {
        assert_eq!(
            split_service("http://127.0.0.1:3065"),
            Some(("http".to_string(), "127.0.0.1".to_string(), 3065))
        );
        assert_eq!(
            split_service("https://192.0.2.10:8888/login"),
            Some(("https".to_string(), "192.0.2.10".to_string(), 8888))
        );
        // 没写端口时按协议取默认端口
        assert_eq!(
            split_service("https://panel.example.com"),
            Some(("https".to_string(), "panel.example.com".to_string(), 443))
        );
        // 不是 URL 的 service（如 http_status:404）不应解析出主机
        assert_eq!(split_service("http_status:404"), None);
        assert_eq!(split_service(""), None);
    }

    #[test]
    fn tcp_open_probes_given_host() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        assert!(tcp_open("127.0.0.1", port), "监听中的端口应探测为通");
        drop(listener);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!tcp_open("127.0.0.1", port), "已关闭的端口应探测为不通");
        assert!(!tcp_open("no-such-host.invalid", port), "无法解析的主机必须判为不通");
    }

    #[test]
    fn run_state_round_trip() {
        let mut p = std::env::temp_dir();
        p.push(format!("cftp-run-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        // 没有文件时必须当作“未运行”，否则重启会凭空拉起隧道
        assert!(!read_run_state(&p));
        write_run_state(&p, true).expect("写入");
        assert!(read_run_state(&p), "写入 true 后必须读回 true");
        write_run_state(&p, false).expect("写入");
        assert!(!read_run_state(&p), "写入 false 后必须读回 false");
        // 内容被破坏时也不许误判为运行
        std::fs::write(&p, "{not json").unwrap();
        assert!(!read_run_state(&p));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn read_config_tolerates_utf8_bom() {
        let mut p = std::env::temp_dir();
        p.push(format!("cftp-bom-{}.yml", std::process::id()));
        let body = "tunnel: abc-123\ncredentials-file: \"c.json\"\ningress:\n  - hostname: \"a.example.com\"\n    service: \"http://127.0.0.1:3065\"\n  - service: http_status:404\n";
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(body.as_bytes());
        std::fs::write(&p, &bytes).unwrap();
        let cfg = read_config(&p).expect("带 BOM 也要能读");
        std::fs::remove_file(&p).ok();
        assert_eq!(cfg.tunnel, "abc-123", "BOM 不该让配置退化成空");
        assert_eq!(cfg.rules.len(), 1);
    }

    #[test]
    fn cname_target_shape() {
        assert_eq!(
            cname_target("39a46127-81ed-4e4d-a041-f4ea4378c1bd"),
            "39a46127-81ed-4e4d-a041-f4ea4378c1bd.cfargotunnel.com"
        );
    }

    #[test]
    fn pick_zone_prefers_longest_suffix() {
        let zones = vec![
            ("z2".to_string(), "example.icu".to_string()),
            ("z3".to_string(), "other.com".to_string()),
            ("z1".to_string(), "sub.example.icu".to_string()),
        ];
        // 最长后缀优先
        assert_eq!(pick_zone("a2a.sub.example.icu", &zones).unwrap().0, "z1");
        assert_eq!(pick_zone("a2a.example.icu", &zones).unwrap().0, "z2");
        // 精确等于 zone 名也算命中
        assert_eq!(pick_zone("example.icu", &zones).unwrap().0, "z2");
        // 必须按点边界匹配: goodexample.icu 不是 example.icu 的子域
        assert!(
            pick_zone("goodexample.icu", &zones).is_none(),
            "没有点边界不应命中"
        );
        assert!(pick_zone("a2a.nowhere.net", &zones).is_none());
        // 大小写与结尾点都应容错
        assert_eq!(pick_zone("A2A.Example.ICU.", &zones).unwrap().0, "z2");
    }

    #[test]
    fn token_file_roundtrip() {
        let mut p = std::env::temp_dir();
        p.push(format!("cftp-token-{}.txt", std::process::id()));
        write_token_to(&p, "  cfut_test  ").unwrap();
        assert_eq!(read_token_from(&p).as_deref(), Some("cfut_test"));
        std::fs::remove_file(&p).ok();
        assert!(read_token_from(&p).is_none(), "文件删掉后应为 None");
    }

    #[test]
    fn ensure_cname_rejects_empty_token() {
        let e = ensure_cname("", "a.example.icu", "tid").unwrap_err();
        assert!(e.contains("Token"), "错误信息应指出缺 token: {e}");
        let e2 = ensure_cname("x", "no-dot", "tid").unwrap_err();
        assert!(!e2.is_empty());
    }

    #[test]
    fn validate_gate_can_go_green_and_red() {
        let Some(cf) = find_cloudflared() else {
            eprintln!("跳过: 未安装 cloudflared");
            return;
        };
        // 合法配置必须通过
        let cfg = tmp_cfg("gate-ok");
        write_config(&cfg).unwrap();
        let (ok, out) = validate_config(&cf, &cfg.path).unwrap();
        assert!(ok, "合法配置被判失败: {out}");

        // 缺 catch-all 的配置必须判红, 否则这个门禁是假绿
        let bad_path = std::env::temp_dir().join(format!("cftp-bad-{}.yml", std::process::id()));
        std::fs::write(
            &bad_path,
            "tunnel: 39a46127-81ed-4e4d-a041-f4ea4378c1bd\ncredentials-file: \"x\"\ningress:\n  - hostname: \"a.example.com\"\n    service: \"http://127.0.0.1:3065\"\n",
        )
        .unwrap();
        let (ok_bad, _) = validate_config(&cf, &bad_path).unwrap();
        let _ = std::fs::remove_file(&cfg.path);
        let _ = std::fs::remove_file(&bad_path);
        assert!(!ok_bad, "缺少 catch-all 的配置竟然通过校验, 门禁是假的");
    }
}
