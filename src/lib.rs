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
    #[serde(default)]
    pub origin: OriginSettings,
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
            origin: OriginSettings::default(),
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

/// Documented cloudflared origin request parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginSettings {
    pub connect_timeout: String,
    #[serde(rename = "tlsTimeout")]
    pub tls_timeout: String,
    pub tcp_keep_alive: String,
    pub keep_alive_timeout: String,
    pub keep_alive_connections: u32,
    pub http2_origin: bool,
    pub disable_chunked_encoding: bool,
    pub http_host_header: String,
    pub origin_server_name: String,
}

impl Default for OriginSettings {
    fn default() -> Self {
        Self { connect_timeout: "30s".into(), tls_timeout: "10s".into(),
            tcp_keep_alive: "30s".into(), keep_alive_timeout: "1m30s".into(),
            keep_alive_connections: 100, http2_origin: false,
            disable_chunked_encoding: false, http_host_header: String::new(),
            origin_server_name: String::new() }
    }
}

fn valid_duration(value: &str) -> bool {
    // Accept bounded integer seconds/minutes/hours, including Go's 1m30s form.
    let mut digits = String::new();
    let mut total: u64 = 0;
    for ch in value.chars() {
        if ch.is_ascii_digit() { digits.push(ch); continue; }
        let multiplier = match ch { 's' => 1, 'm' => 60, 'h' => 3600, _ => return false };
        let Ok(n) = digits.parse::<u64>() else { return false; };
        let Some(next) = n.checked_mul(multiplier).and_then(|v| total.checked_add(v)) else { return false; };
        total = next;
        digits.clear();
    }
    digits.is_empty() && total > 0 && total <= 86400
}

impl OriginSettings {
    pub fn validate(&self, service: &str) -> Result<(), String> {
        for value in [&self.connect_timeout, &self.tls_timeout, &self.tcp_keep_alive, &self.keep_alive_timeout] {
            if !valid_duration(value) { return Err("超时必须是 1s–24h 范围的时长，例如 30s、1m30s".into()); }
        }
        if self.keep_alive_connections > 10000 { return Err("空闲连接数不能超过 10000".into()); }
        if self.http2_origin && !service.starts_with("https://") { return Err("HTTP/2 源站需要使用 HTTPS".into()); }
        for value in [&self.http_host_header, &self.origin_server_name] {
            if value.len() > 255 || value.chars().any(char::is_control) { return Err("Host / TLS 名称不合法".into()); }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConnectionSettings {
    pub protocol: String,
    pub edge_ip_version: String,
    pub region: String,
    pub loglevel: String,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self { protocol: "http2".into(), edge_ip_version: "4".into(), region: String::new(), loglevel: "info".into() }
    }
}

impl ConnectionSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !["auto", "http2", "quic"].contains(&self.protocol.as_str()) { return Err("连接协议不合法".into()); }
        if !["auto", "4", "6"].contains(&self.edge_ip_version.as_str()) { return Err("IP 版本不合法".into()); }
        if !["", "us"].contains(&self.region.as_str()) { return Err("区域仅支持全局或 us，不能指定 apac".into()); }
        if !["debug", "info", "warn", "error", "fatal"].contains(&self.loglevel.as_str()) { return Err("日志级别不合法".into()); }
        Ok(())
    }
    pub fn args(&self) -> Vec<String> {
        vec!["--protocol".into(), self.protocol.clone(), "--edge-ip-version".into(), self.edge_ip_version.clone(),
            "--region".into(), self.region.clone(), "--loglevel".into(), self.loglevel.clone()]
    }
}

/// cloudflared 的 yml 配置。
#[derive(Debug, Clone, Default)]
pub struct TunnelConfig {
    pub path: PathBuf,
    pub tunnel: String,
    pub credentials_file: String,
    pub rules: Vec<Rule>,
    pub connection: ConnectionSettings,
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
    let mut connection = serde_json::to_value(ConnectionSettings::default()).unwrap();
    for key in ["protocol", "edge-ip-version", "region", "loglevel"] {
        if let Some(v) = value.get(key) {
            connection[key] = serde_json::Value::String(v.as_str().map(str::to_owned).unwrap_or_else(|| v.as_i64().unwrap_or_default().to_string()));
        }
    }
    cfg.connection = serde_json::from_value(connection).map_err(|e| CoreError::Yaml(e.to_string()))?;
    if let Some(list) = value.get("ingress").and_then(|v| v.as_sequence()) {
        for item in list {
            let host = item.get("hostname").and_then(|v| v.as_str());
            let svc = item.get("service").and_then(|v| v.as_str());
            if let (Some(h), Some(s)) = (host, svc) {
                let no_tls = item
                    .get("originRequest")
                    .and_then(|v| v.get("noTLSVerify"))
                    .or_else(|| value.get("originRequest").and_then(|v| v.get("noTLSVerify")))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let enabled = item.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
                let note = item
                    .get("note")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let mut origin = serde_json::to_value(OriginSettings::default()).unwrap();
                for source in [value.get("originRequest"), item.get("originRequest")].into_iter().flatten() {
                    for key in ["connectTimeout", "tlsTimeout", "tcpKeepAlive", "keepAliveTimeout", "keepAliveConnections", "http2Origin", "disableChunkedEncoding", "httpHostHeader", "originServerName"] {
                        if let Some(v) = source.get(key) { origin[key] = serde_json::to_value(v).unwrap(); }
                    }
                }
                let origin = serde_json::from_value(origin).map_err(|e| CoreError::Yaml(e.to_string()))?;
                cfg.rules.push(Rule {
                    hostname: h.to_owned(),
                    service: s.to_owned(),
                    no_tls_verify: no_tls,
                    origin,
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
    s.push_str(&serde_yaml::to_string(&cfg.connection).unwrap());
    s.push_str("ingress:\n");
    for r in cfg.rules.iter().filter(|r| r.enabled) {
        s.push_str(&format!("  - hostname: {}\n", yaml_quote(&r.hostname)));
        s.push_str(&format!("    service: {}\n", yaml_quote(&r.service)));
        s.push_str("    originRequest:\n");
        let origin = serde_yaml::to_string(&r.origin).unwrap();
        for line in origin.lines() { s.push_str(&format!("      {line}\n")); }
        s.push_str(&format!("      noTLSVerify: {}\n", r.no_tls_verify));
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

/// Update only runtime keys; preserve ingress and any manually configured options.
pub fn write_connection_settings(path: &Path, settings: &ConnectionSettings) -> Result<(), CoreError> {
    settings.validate().map_err(CoreError::Yaml)?;
    let text = if path.exists() { std::fs::read_to_string(path)? } else { String::new() };
    let mut value: serde_yaml::Value = if text.trim().is_empty() { serde_yaml::Value::Mapping(Default::default()) }
        else { serde_yaml::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| CoreError::Yaml(e.to_string()))? };
    let map = value.as_mapping_mut().ok_or_else(|| CoreError::Yaml("配置根节点必须是对象".into()))?;
    if let serde_yaml::Value::Mapping(next) = serde_yaml::to_value(settings).unwrap() { map.extend(next); }
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(path, serde_yaml::to_string(&value).map_err(|e| CoreError::Yaml(e.to_string()))?)?;
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
    let mut cmd = Command::new(cf);
    cmd.args(["tunnel", "list"]).stdout(Stdio::piped()).stderr(Stdio::piped());
    hidden(&mut cmd);
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_owned()).into());
    }
    let out = String::from_utf8_lossy(&out.stdout);
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

#[cfg(unix)]
pub fn read_cpu_times() -> Option<(u64, u64)> {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|t| parse_proc_stat_cpu(&t))
}

#[cfg(unix)]
pub fn read_mem() -> Option<(u64, u64)> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| parse_meminfo(&t))
}

#[cfg(unix)]
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

#[cfg(unix)]
pub fn read_uptime_secs() -> Option<f64> {
    let t = std::fs::read_to_string("/proc/uptime").ok()?;
    t.split_whitespace().next()?.parse::<f64>().ok()
}

#[cfg(unix)]
pub fn read_net_totals() -> Option<(u64, u64)> {
    std::fs::read_to_string("/proc/net/dev")
        .ok()
        .and_then(|t| parse_net_dev(&t))
}

#[cfg(unix)]
pub fn read_self_rss_kb() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = t.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

/// 磁盘用量（KB）：直接调用 df，避免为 statvfs 引入额外依赖。
#[cfg(unix)]
pub fn disk_usage(path: &str) -> Option<(u64, u64)> {
    let mut cmd = Command::new("df");
    cmd.args(["-k", path]);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_df_kb(&String::from_utf8_lossy(&out.stdout))
}

// ------------------------------------------------------------------ Windows 采集

/// Windows 走 Win32：CPU 用 GetSystemTimes，内存 GlobalMemoryStatusEx，
/// 网卡 GetIfTable2，进程内存 GetProcessMemoryInfo，磁盘 GetDiskFreeSpaceExW。
#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::SystemInformation::{
        GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetSystemTimes};

    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

    fn filetime_u64(ft: &FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
    }

    pub fn cpu() -> Option<(u64, u64)> {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut idle = zero;
        let mut kernel = zero;
        let mut user = zero;
        let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
        if ok == 0 {
            return None;
        }
        // GetSystemTimes 的 kernel 时间已包含 idle，总量 = kernel + user
        Some((filetime_u64(&idle), filetime_u64(&kernel) + filetime_u64(&user)))
    }

    pub fn mem_kb() -> Option<(u64, u64)> {
        let mut st: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        st.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        let ok = unsafe { GlobalMemoryStatusEx(&mut st) };
        if ok == 0 {
            return None;
        }
        Some((st.ullTotalPhys / 1024, st.ullAvailPhys / 1024))
    }

    pub fn uptime_secs() -> Option<f64> {
        Some(unsafe { GetTickCount64() } as f64 / 1000.0)
    }

    pub fn net_totals() -> Option<(u64, u64)> {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let rc = unsafe { GetIfTable2(&mut table) };
        if rc != 0 || table.is_null() {
            return None;
        }
        let mut rx = 0u64;
        let mut tx = 0u64;
        unsafe {
            let rows = (*table).NumEntries as usize;
            let base = (*table).Table.as_ptr();
            for i in 0..rows {
                let row = &*base.add(i);
                if row.Type == IF_TYPE_SOFTWARE_LOOPBACK {
                    continue;
                }
                rx = rx.saturating_add(row.InOctets);
                tx = tx.saturating_add(row.OutOctets);
            }
            FreeMibTable(table as *const _);
        }
        Some((rx, tx))
    }

    pub fn self_rss_kb() -> Option<u64> {
        let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) };
        if ok == 0 {
            return None;
        }
        Some(pmc.WorkingSetSize as u64 / 1024)
    }

    pub fn disk_kb() -> Option<(u64, u64)> {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let mut root: Vec<u16> = format!("{drive}\\").encode_utf16().collect();
        root.push(0);
        let mut free = 0u64;
        let mut total = 0u64;
        let ok = unsafe {
            GetDiskFreeSpaceExW(root.as_ptr(), &mut free, &mut total, std::ptr::null_mut())
        };
        if ok == 0 {
            return None;
        }
        Some((total.saturating_sub(free) / 1024, total / 1024))
    }
}

#[cfg(windows)]
pub fn read_cpu_times() -> Option<(u64, u64)> {
    win::cpu()
}

#[cfg(windows)]
pub fn read_mem() -> Option<(u64, u64)> {
    win::mem_kb()
}

/// Windows 没有 loadavg 语义，返回 None（界面显示 "-" 而不是编一个数字）
#[cfg(windows)]
pub fn read_loadavg() -> Option<(f64, f64, f64)> {
    None
}

#[cfg(windows)]
pub fn read_uptime_secs() -> Option<f64> {
    win::uptime_secs()
}

#[cfg(windows)]
pub fn read_net_totals() -> Option<(u64, u64)> {
    win::net_totals()
}

#[cfg(windows)]
pub fn read_self_rss_kb() -> Option<u64> {
    win::self_rss_kb()
}

#[cfg(windows)]
pub fn disk_usage(_path: &str) -> Option<(u64, u64)> {
    win::disk_kb()
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
        let settings = read_config(cfg).map_err(std::io::Error::other)?.connection;
        settings.validate().map_err(std::io::Error::other)?;
        let mut args = vec!["tunnel".into(), "--config".into(), cfg.to_string_lossy().into_owned()];
        args.extend(settings.args());
        args.push("run".into());
        self.spawn_with(cf, args)
    }

    pub fn start_with_token(&mut self, cf: &Path, token: &str, settings: &ConnectionSettings) -> std::io::Result<()> {
        settings.validate().map_err(std::io::Error::other)?;
        let mut args = vec!["tunnel".into()];
        args.extend(settings.args());
        args.extend(["run".into(), "--token".into(), token.trim().into()]);
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
    let req = req.timeout(std::time::Duration::from_secs(20)).set("Authorization", &format!("Bearer {token}"));
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

pub fn zone_settings(token: &str, hostname: &str) -> Result<serde_json::Value, String> {
    validate_hostname(hostname)?;
    let zones = list_zones(token)?;
    let zone = pick_zone(hostname, &zones).ok_or("域名不在 Token 可见的 Zone 中")?;
    let result = cf_call("GET", &format!("{CF_API}/zones/{}/settings", zone.0), token, None)?;
    let mut settings = serde_json::Map::new();
    for item in result["result"].as_array().ok_or("Cloudflare 未返回设置列表")? {
        if let Some(id) = item["id"].as_str() {
            if ["ssl", "always_use_https", "rocket_loader"].contains(&id) {
                settings.insert(id.into(), serde_json::json!({"value": item["value"], "editable": item["editable"]}));
            }
        }
    }
    Ok(serde_json::json!({"zone": zone.1, "settings": settings}))
}

pub fn update_zone_setting(token: &str, hostname: &str, setting: &str, value: &str) -> Result<(), String> {
    validate_hostname(hostname)?;
    let valid = match setting {
        "ssl" => ["strict", "full", "flexible", "off"].contains(&value),
        "always_use_https" | "rocket_loader" => ["on", "off"].contains(&value),
        _ => false,
    };
    if !valid { return Err("不支持的云端设置或值".into()); }
    let zones = list_zones(token)?;
    let zone = pick_zone(hostname, &zones).ok_or("域名不在 Token 可见的 Zone 中")?;
    let result = cf_call("PATCH", &format!("{CF_API}/zones/{}/settings/{setting}", zone.0), token,
        Some(serde_json::json!({"value": value})))?;
    if result["success"] != true { return Err("Cloudflare 未确认保存成功".into()); }
    Ok(())
}

pub fn cache_bypass_rule(hostname: &str, prefix: &str) -> Result<serde_json::Value, String> {
    validate_hostname(hostname)?;
    if !prefix.starts_with('/') || prefix.len() > 1024 || prefix.chars().any(char::is_control) {
        return Err("路径前缀必须以 / 开头，且不能包含控制字符".into());
    }
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    let expression = format!("(http.host eq {} and starts_with(http.request.uri.path, {}))", quote(hostname), quote(prefix));
    let hash = expression.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
    Ok(serde_json::json!({"ref": format!("cftp_api_{hash:x}"), "description": format!("Tunnel Panel: bypass {hostname}{prefix}"),
        "expression": expression, "action": "set_cache_settings", "action_parameters": {"cache": false}, "enabled": true}))
}

/// Append/update only the panel-owned rule; never replace the zone's entire ruleset.
pub fn apply_cache_bypass(token: &str, hostname: &str, prefix: &str) -> Result<(), String> {
    let rule = cache_bypass_rule(hostname, prefix)?;
    apply_managed_rule(token, hostname, "http_request_cache_settings", rule)
}

pub fn configuration_rule(hostname: &str, prefix: &str, request: &str, response: &str, rocket: &str) -> Result<serde_json::Value, String> {
    let base = cache_bypass_rule(hostname, prefix)?;
    if !["", "standard", "full", "none"].contains(&request)
        || !["", "standard", "none"].contains(&response)
        || !["", "on", "off"].contains(&rocket) { return Err("缓冲或 Rocket Loader 设置不合法".into()); }
    let mut params = serde_json::Map::new();
    if !request.is_empty() { params.insert("request_body_buffering".into(), request.into()); }
    if !response.is_empty() { params.insert("response_body_buffering".into(), response.into()); }
    if !rocket.is_empty() { params.insert("rocket_loader".into(), (rocket == "on").into()); }
    if params.is_empty() { return Err("至少选择一项云端配置".into()); }
    Ok(serde_json::json!({"ref":base["ref"].as_str().unwrap().replace("cftp_api_", "cftp_config_"),
        "description":format!("Tunnel Panel: configuration {hostname}{prefix}"), "expression":base["expression"],
        "action":"set_config", "action_parameters":params, "enabled":true}))
}

pub fn apply_configuration_rule(token: &str, hostname: &str, prefix: &str, request: &str, response: &str, rocket: &str) -> Result<(), String> {
    apply_managed_rule(token, hostname, "http_config_settings", configuration_rule(hostname, prefix, request, response, rocket)?)
}

fn apply_managed_rule(token: &str, hostname: &str, phase: &str, rule: serde_json::Value) -> Result<(), String> {
    let zones = list_zones(token)?;
    let zone = pick_zone(hostname, &zones).ok_or("域名不在 Token 可见的 Zone 中")?;
    let base = format!("{CF_API}/zones/{}/rulesets", zone.0);
    let list = cf_call("GET", &base, token, None)?;
    let sets = list["result"].as_array().ok_or("Cloudflare 未返回规则集")?;
    let existing = sets.iter().find(|v| v["phase"] == phase && v["kind"] == "zone");
    let result = if let Some(set) = existing {
        let id = set["id"].as_str().ok_or("规则集缺少 ID")?;
        let current = cf_call("GET", &format!("{base}/{id}"), token, None)?;
        let own = current["result"]["rules"].as_array().and_then(|rules| rules.iter().find(|r| r["ref"] == rule["ref"]));
        if let Some(own) = own {
            let rid = own["id"].as_str().ok_or("规则缺少 ID")?;
            cf_call("PATCH", &format!("{base}/{id}/rules/{rid}"), token, Some(rule))?
        } else {
            cf_call("POST", &format!("{base}/{id}/rules"), token, Some(rule))?
        }
    } else {
        cf_call("POST", &base, token, Some(serde_json::json!({"name":"Tunnel Panel API rules", "kind":"zone", "phase":phase, "rules":[rule]})))?
    };
    if result["success"] != true { return Err("Cloudflare 未确认规则保存成功".into()); }
    Ok(())
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
            connection: ConnectionSettings::default(),
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
            connection: ConnectionSettings::default(),
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
    fn advanced_settings_roundtrip_and_real_validation() {
        let mut cfg = tmp_cfg("advanced");
        cfg.connection.protocol = "http2".into();
        cfg.connection.edge_ip_version = "auto".into();
        cfg.connection.region = "us".into();
        cfg.rules[0].service = "https://127.0.0.1:8443".into();
        cfg.rules[0].origin.http2_origin = true;
        cfg.rules[0].origin.connect_timeout = "45s".into();
        cfg.rules[0].origin.keep_alive_connections = 256;
        cfg.rules[0].origin.http_host_header = "internal.example.com".into();
        cfg.rules[0].origin.origin_server_name = "internal.example.com".into();
        cfg.rules[0].no_tls_verify = true;
        write_config(&cfg).unwrap();
        let restored = read_config(&cfg.path).unwrap();
        assert_eq!(restored.connection, cfg.connection);
        assert_eq!(restored.rules, cfg.rules);
        if let Some(cf) = find_cloudflared() {
            let (ok, output) = validate_config(&cf, &cfg.path).unwrap();
            assert!(ok, "{output}");
        }
        std::fs::remove_file(&cfg.path).ok();
    }

    #[test]
    fn origin_validation_rejects_invalid_settings() {
        let mut origin = OriginSettings::default();
        assert!(origin.validate("http://localhost:80").is_ok());
        origin.http2_origin = true;
        assert!(origin.validate("http://localhost:80").is_err());
        assert!(origin.validate("https://localhost:443").is_ok());
        for duration in ["0s", "-1s", "garbage", "999999999999999999999999h", "25h", "30"] {
            origin.connect_timeout = duration.into();
            assert!(origin.validate("https://localhost:443").is_err(), "{duration}");
        }
        assert!(valid_duration("1m30s"));
        assert!(valid_duration("24h"));
    }

    #[test]
    fn http2_default_preserves_explicit_protocols() {
        assert_eq!(ConnectionSettings::default().protocol, "http2");
        assert_eq!(serde_json::from_str::<ConnectionSettings>("{}").unwrap().protocol, "http2");
        assert!(ConnectionSettings::default().args().windows(2).any(|args| args == ["--protocol", "http2"]));
        let cfg = tmp_cfg("http2-default");
        assert_eq!(read_config(&cfg.path).unwrap().connection.protocol, "http2");
        for explicit in [None, Some("auto"), Some("quic"), Some("http2")] {
            let mut text = "tunnel: test-default\ningress:\n  - service: http_status:404\n".to_string();
            if let Some(value) = explicit { text.push_str(&format!("protocol: {value}\n")); }
            std::fs::write(&cfg.path, text).unwrap();
            let loaded = read_config(&cfg.path).unwrap();
            assert_eq!(loaded.connection.protocol, explicit.unwrap_or("http2"));
            write_config(&loaded).unwrap();
            assert_eq!(read_config(&cfg.path).unwrap().connection.protocol, explicit.unwrap_or("http2"));
        }
        std::fs::remove_file(&cfg.path).unwrap();
    }

    #[test]
    fn connection_validation_and_launch_arguments() {
        let mut settings = ConnectionSettings::default();
        assert!(settings.validate().is_ok());
        settings.protocol = "http2".into();
        assert!(settings.args().windows(2).any(|a| a == ["--protocol", "http2"]));
        settings.region = "apac".into();
        assert!(settings.validate().is_err());
        settings.region.clear();
        settings.edge_ip_version = "5".into();
        assert!(settings.validate().is_err());
    }

    #[test]
    fn runtime_save_preserves_unmanaged_yaml_and_global_origin() {
        let cfg = tmp_cfg("preserve");
        std::fs::write(&cfg.path, "tunnel: demo\nmetrics: localhost:9001\noriginRequest:\n  connectTimeout: 42s\n  noTLSVerify: true\ningress:\n  - hostname: api.example.com\n    service: https://localhost:443\n  - service: http_status:404\n").unwrap();
        let settings = ConnectionSettings { protocol: "http2".into(), ..Default::default() };
        write_connection_settings(&cfg.path, &settings).unwrap();
        let text = std::fs::read_to_string(&cfg.path).unwrap();
        assert!(text.contains("metrics: localhost:9001"));
        let restored = read_config(&cfg.path).unwrap();
        assert_eq!(restored.rules[0].origin.connect_timeout, "42s");
        assert!(restored.rules[0].no_tls_verify);
        assert_eq!(restored.connection, settings);
        std::fs::remove_file(&cfg.path).ok();
    }

    #[test]
    fn legacy_rules_receive_defaults_and_disabled_rules_keep_options() {
        let rules: Vec<Rule> = serde_json::from_str(r#"[{"hostname":"a.example.com","service":"http://localhost:8080"}]"#).unwrap();
        assert_eq!(rules[0].origin, OriginSettings::default());
        let mut rule = rules[0].clone();
        rule.enabled = false;
        rule.origin.connect_timeout = "42s".into();
        let cfg = tmp_cfg("sidecar-advanced");
        let path = rules_sidecar(&cfg.path);
        write_rules_sidecar(&path, &[rule.clone()]).unwrap();
        assert_eq!(read_rules_sidecar(&path).unwrap(), vec![rule]);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn cache_rule_scope_is_escaped_and_stable() {
        let rule = cache_bypass_rule("api.example.com", "/hu").unwrap();
        assert_eq!(rule["action_parameters"]["cache"], false);
        assert_eq!(rule["expression"], r#"(http.host eq "api.example.com" and starts_with(http.request.uri.path, "/hu"))"#);
        assert_eq!(rule["ref"], cache_bypass_rule("api.example.com", "/hu").unwrap()["ref"]);
        assert_ne!(rule["ref"], cache_bypass_rule("api.example.com", "/other").unwrap()["ref"]);
        assert!(cache_bypass_rule("api.example.com", "api").is_err());
        assert!(cache_bypass_rule("bad host", "/").is_err());
        assert!(cache_bypass_rule("api.example.com", "/\n").is_err());
        assert!(cache_bypass_rule("api.example.com", "/\" or true").unwrap()["expression"].as_str().unwrap().contains("\\\""));
    }

    #[test]
    fn buffering_rule_only_emits_selected_supported_parameters() {
        let rule = configuration_rule("api.example.com", "/hu", "none", "none", "off").unwrap();
        assert_eq!(rule["action"], "set_config");
        assert_eq!(rule["action_parameters"], serde_json::json!({"request_body_buffering":"none","response_body_buffering":"none","rocket_loader":false}));
        let partial = configuration_rule("api.example.com", "/hu", "standard", "", "").unwrap();
        assert_eq!(partial["action_parameters"].as_object().unwrap().len(), 1);
        assert_eq!(rule["ref"], partial["ref"]);
        assert_ne!(rule["ref"], cache_bypass_rule("api.example.com", "/hu").unwrap()["ref"]);
        assert!(configuration_rule("api.example.com", "/hu", "", "", "").is_err());
        assert!(configuration_rule("api.example.com", "/hu", "", "full", "").is_err());
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
