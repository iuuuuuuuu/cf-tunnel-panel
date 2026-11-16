#![cfg_attr(windows, windows_subsystem = "windows")]

//! 桌面端托盘：不再提供 GUI 窗口，只把浏览器里的 Web 面板拉起来。
//!
//! 职责：
//! 1. 首次运行时生成面板口令并写入 panel-desktop-password.txt
//! 2. 用隐藏窗口方式拉起同目录的 cf-tunnel-server.exe（只监听 127.0.0.1:8788）
//! 3. 提供托盘菜单：打开面板 / 复制地址 / 打开配置目录 / 退出

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

const BIND: &str = "127.0.0.1";
const PORT: u16 = 8788;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 托盘拉起的服务端 pid，退出时顺手停掉
static SERVER_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn cf_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cloudflared")
}

fn panel_config() -> PathBuf {
    if let Ok(p) = std::env::var("PANEL_CONFIG") {
        return PathBuf::from(p);
    }
    cf_dir().join("panel.json")
}

fn server_exe() -> PathBuf {
    let mut p = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("cf-tunnel-server.exe"));
    p.set_file_name("cf-tunnel-server.exe");
    p
}

fn panel_url() -> String {
    format!("http://{}:{}/", BIND, PORT)
}

fn log(msg: &str) {
    let dir = cf_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("tray.log");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

fn rand_hex(n: usize) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    while out.len() < n {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        h.write_u32(std::process::id());
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out.truncate(n);
    out
}

fn hidden(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// 端口上已有服务在跑（可能是上一次留下的，也可能是用户自己启的）
fn port_alive() -> bool {
    std::net::TcpStream::connect_timeout(
        &format!("{}:{}", BIND, PORT).parse().unwrap(),
        Duration::from_millis(400),
    )
    .is_ok()
}

/// 首次运行生成口令；返回 Some(口令) 表示这次是新生成的。
fn ensure_password() -> Option<String> {
    let cfg = panel_config();
    let text = std::fs::read_to_string(&cfg).unwrap_or_default();
    let has_password = text.contains("\"password_hash\"")
        && !text.contains("\"password_hash\":\"\"")
        && !text.contains("\"password_hash\": \"\"");
    if has_password {
        return None;
    }
    let pw = rand_hex(16);
    let exe = server_exe();
    let status = hidden(&mut Command::new(&exe))
        .arg("--set-password")
        .env("PANEL_PASSWORD", &pw)
        .env("PANEL_CONFIG", cfg.to_string_lossy().to_string())
        .env("PANEL_LOCAL_NO_AUTH", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {
            let dir = cf_dir();
            let _ = std::fs::create_dir_all(&dir);
            let pw_file = dir.join("panel-desktop-password.txt");
            let _ = std::fs::write(&pw_file, format!("{pw}\n"));
            log(&format!("已生成面板口令: {}", pw_file.display()));
            Some(pw)
        }
        other => {
            log(&format!("设置口令失败: {:?}（server_exe={}）", other, exe.display()));
            None
        }
    }
}

fn spawn_server() -> bool {
    if port_alive() {
        log("面板已在运行，跳过启动");
        return true;
    }
    let exe = server_exe();
    if !exe.is_file() {
        log(&format!("找不到 {}，请把 cf-tunnel-server.exe 放在同目录", exe.display()));
        return false;
    }
    let cfg = panel_config();
    let spawned = hidden(&mut Command::new(&exe))
        .args(["--bind", BIND, "--port", &PORT.to_string()])
        .env("PANEL_CONFIG", cfg.to_string_lossy().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawned {
        Ok(child) => {
            SERVER_PID.store(child.id(), std::sync::atomic::Ordering::SeqCst);
            log(&format!("已启动面板服务 pid={}", child.id()));
            true
        }
        Err(e) => {
            log(&format!("启动面板服务失败: {e}"));
            false
        }
    }
}

fn open_url(url: &str) {
    let _ = hidden(&mut Command::new("cmd"))
        .args(["/C", "start", "", url])
        .status();
}

fn copy_text(text: &str) {
    let _ = hidden(&mut Command::new("cmd"))
        .args(["/C", "echo "])
        .arg(text)
        .arg("| clip")
        .stdout(Stdio::null())
        .status();
}

fn open_dir() {
    let dir = cf_dir();
    let _ = hidden(&mut Command::new("explorer")).arg(dir).status();
}

fn load_icon() -> Option<Icon> {
    let rgba = include_bytes!("../../assets/tray-32.rgba");
    if rgba.len() != 32 * 32 * 4 {
        log("托盘图标数据长度不对");
        return None;
    }
    Icon::from_rgba(rgba.to_vec(), 32, 32).ok()
}

#[cfg(windows)]
fn pump_messages() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, TranslateMessage, MSG,
    };
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

fn main() {
    log("托盘启动");

    let fresh = ensure_password();
    let started = spawn_server();

    let menu = Menu::new();
    let open_item = MenuItem::with_id("open", "打开面板", true, None);
    let copy_item = MenuItem::with_id("copy", "复制面板地址", true, None);
    let dir_item = MenuItem::with_id("dir", "打开配置目录", true, None);
    let quit_item = MenuItem::with_id("quit", "退出", true, None);
    let _ = menu.append(&open_item);
    let _ = menu.append(&copy_item);
    let _ = menu.append(&dir_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    let tooltip = if started {
        format!("内网穿透面板 · {}", panel_url())
    } else {
        "内网穿透面板 · 服务未启动（看 ~/.cloudflared/tray.log）".to_string()
    };

    let mut builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(tooltip)
        .with_menu_on_left_click(true);
    if let Some(icon) = load_icon() {
        builder = builder.with_icon(icon);
    }
    // 句柄必须一直持有，否则托盘图标会消失
    let _tray = match builder.build() {
        Ok(t) => t,
        Err(e) => {
            log(&format!("托盘创建失败: {e}"));
            return;
        }
    };

    if let Some(pw) = fresh {
        log("首次运行：口令已生成，保存在 panel-desktop-password.txt");
        open_url(&panel_url());
        let _ = pw;
    }

    // 菜单事件在自己的线程里轮询，主线程只管消息泵
    std::thread::spawn(move || loop {
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            match ev.id.0.as_str() {
                "open" => open_url(&panel_url()),
                "copy" => copy_text(&panel_url()),
                "dir" => open_dir(),
                "quit" => {
                    // 托盘句柄留在主线程（Rc，不能跨线程），退出时交给系统回收
                    let pid = SERVER_PID.load(std::sync::atomic::Ordering::SeqCst);
                    if pid != 0 {
                        let _ = hidden(&mut Command::new("taskkill"))
                            .args(["/PID", &pid.to_string(), "/F"])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                        log(&format!("已停止面板服务 pid={pid}"));
                    }
                    log("托盘退出");
                    std::process::exit(0);
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(80));
    });

    #[cfg(windows)]
    pump_messages();

    std::thread::park();
}
