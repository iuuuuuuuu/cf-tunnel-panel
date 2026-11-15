use super::*;
use std::process::{Command,Stdio};

// curl uses the host's DNS/TLS implementation, and its native timing metrics include DNS.
// --head with --request GET sends GET but stops after response headers, including SSE.
pub(super) fn sample(url:&str,timeout_ms:u64)->serde_json::Value {
    let timeout=timeout_ms.clamp(1000,20000) as f64/1000.;
    let mut cmd=Command::new(if cfg!(windows){"curl.exe"}else{"curl"});
    cmd.args(["-q","--noproxy","*","--silent","--show-error","--head","--request","GET",
        "--proto","=https","--max-redirs","0","--max-time",&timeout.to_string(),
        "--connect-timeout",&timeout.min(8.).to_string(),"--user-agent","Mozilla/5.0 TunnelPanel-Diagnostics",
        "--header","Cache-Control: no-cache","--write-out","\nCFTP:%{json}","--url",url])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)] {use std::os::windows::process::CommandExt;cmd.creation_flags(0x08000000);}
    let started=Instant::now();
    let mut child=match cmd.spawn(){Ok(c)=>c,Err(_)=>return serde_json::json!({"source":"panel-server","elapsed_ms":0,"status":null,"timing":null,"error":"服务器缺少 curl，安装 curl 后可进行主机内部诊断"})};
    let stdout=child.stdout.take().unwrap();
    let reader=std::thread::spawn(move||{let mut text=String::new();let _=stdout.take(128*1024).read_to_string(&mut text);text});
    let deadline=Duration::from_millis(timeout_ms+1500);
    let status=loop{match child.try_wait(){Ok(Some(status))=>break Some(status),Ok(None)if started.elapsed()<deadline=>std::thread::sleep(Duration::from_millis(20)),_=>{let _=child.kill();let _=child.wait();break None}}};
    let text=reader.join().unwrap_or_default();
    let value=text.rsplit_once("\nCFTP:").and_then(|(_,text)|serde_json::from_str::<serde_json::Value>(text.trim()).ok());
    let Some(v)=value else{return serde_json::json!({"source":"panel-server","elapsed_ms":started.elapsed().as_secs_f64()*1000.,"status":null,"timing":null,"error":"服务器探测超时或无法读取 curl 计时结果"})};
    let code=v["http_code"].as_u64().filter(|n|*n>0);
    let ms=|key:&str|v[key].as_f64().unwrap_or(0.)*1000.;
    let dns=ms("time_namelookup");let connect=ms("time_connect");let tls=ms("time_appconnect");let pre=ms("time_pretransfer");let first=ms("time_starttransfer");
    serde_json::json!({"source":"panel-server","server":std::env::consts::OS,
        "elapsed_ms":ms("time_total"),"status":code,
        "timing":if code.is_some(){serde_json::json!({"dnsMs":dns,"connectMs":(connect-dns).max(0.),"tlsMs":if tls>0.{Some((tls-connect).max(0.))}else{None},"ttfbMs":(first-pre).max(0.),"protocol":v["http_version"]})}else{serde_json::Value::Null},
        "error":if status.is_some_and(|s|s.success())&&code.is_some(){None}else{Some("服务器 DNS/TLS、连接失败或请求超时；不跟随重定向")},
        "measured":"面板所在主机 → 公网域名；匿名 GET，仅响应头，不跟随重定向"})
}
