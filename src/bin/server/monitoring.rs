use super::*;
use std::io::{BufRead, BufReader};
use chrono::NaiveDate;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const RETENTION: u64 = 90 * 86400;
const HOLD: u64 = 300;
const COOLDOWN: u64 = 3600;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct AlertConfig {
    pub cpu_pct: f64,
    pub memory_pct: f64,
    pub disk_pct: f64,
    pub pushplus_enabled: bool,
}
impl Default for AlertConfig {
    fn default() -> Self { Self { cpu_pct: 85., memory_pct: 90., disk_pct: 90., pushplus_enabled: false } }
}
#[derive(Default, Serialize, Deserialize)]
struct ThresholdState {
    since: Option<u64>,
    last: Option<u64>,
    last_event: Option<u64>,
    active: bool,
}
#[derive(Default, Serialize, Deserialize)]
struct AlertState { thresholds: BTreeMap<String, ThresholdState> }
#[derive(Serialize, Deserialize, Clone)]
struct Event { at: u64, level: String, message: String, channel: Option<String> }

pub(super) struct Monitor {
    dir: PathBuf,
    cfg: Mutex<AlertConfig>,
    state: Mutex<AlertState>,
    io: Mutex<()>,
    pub latest: Mutex<Value>,
    error: Mutex<Option<String>>,
}

fn private_file(path: &Path, append: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).append(append).truncate(!append);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let file = options.open(path)?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; file.set_permissions(std::fs::Permissions::from_mode(0o600))?; }
    Ok(file)
}
fn save_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e|e.to_string())?;
    private_file(path, false).and_then(|mut f|f.write_all(&bytes)).map_err(|e|e.to_string())
}
fn date_name(at: u64) -> String {
    chrono::DateTime::from_timestamp(at as i64, 0).unwrap_or_default().format("%Y-%m-%d").to_string()
}
fn date_epoch(text: &str) -> Option<u64> {
    let d=NaiveDate::parse_from_str(text,"%Y-%m-%d").ok()?;
    let value=d.and_hms_opt(0,0,0)?.and_utc().timestamp();
    (value>=0).then_some(value as u64)
}
fn query(req: &Request, key: &str) -> Option<String> {
    let (_, q)=req.url().split_once('?')?;
    url::form_urlencoded::parse(q.as_bytes()).find(|(k,_)|k==key).map(|(_,v)|v.into_owned())
}
fn range(req: &Request) -> Result<(u64,u64),String> {
    let now=now_unix();
    let parse=|key:&str| -> Result<Option<u64>,String> {
        query(req,key).map(|value|value.parse::<u64>().ok().or_else(||date_epoch(&value)).ok_or_else(||format!("{key} 日期不合法"))).transpose()
    };
    let from=parse("from")?.unwrap_or(now.saturating_sub(7*86400));
    let to=parse("to")?.map(|v| if query(req,"to").is_some_and(|x|x.contains('-')) {v+86400}else{v}).unwrap_or(now+1);
    if from>=to || to.saturating_sub(from)>RETENTION+86400 || from<now.saturating_sub(RETENTION+86400) || to>now+86401 {
        return Err("请选择最近 90 天内的有效日期范围".into());
    }
    Ok((from,to))
}
fn percentage(used: f64,total:f64)->Option<f64> { (total>0.&&used.is_finite()).then_some((used/total*100.).clamp(0.,100.)) }

impl Monitor {
    pub fn new(config: &Path) -> Result<Arc<Self>,String> {
        let dir=config.parent().unwrap_or(Path::new(".")).join("monitoring");
        std::fs::create_dir_all(dir.join("metrics")).map_err(|e|e.to_string())?;
        std::fs::create_dir_all(dir.join("events")).map_err(|e|e.to_string())?;
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;}
        let load=|file:&str|std::fs::read_to_string(dir.join(file)).ok();
        let cfg=match load("alerts.json") {Some(text)=>serde_json::from_str(&text).map_err(|_|"告警配置损坏，请检查 monitoring/alerts.json".to_string())?,None=>AlertConfig::default()};
        let state=load("alert-state.json").and_then(|t|serde_json::from_str(&t).ok()).unwrap_or_default();
        Ok(Arc::new(Self{dir,cfg:Mutex::new(cfg),state:Mutex::new(state),io:Mutex::new(()),latest:Mutex::new(json!({})),error:Mutex::new(None)}))
    }
    fn token(&self) -> String { std::fs::read_to_string(self.dir.join("pushplus.token")).unwrap_or_default().trim().to_owned() }
    fn append(&self, kind:&str, at:u64, value:&impl Serialize) -> Result<(),String> {
        let _io=self.io.lock().unwrap();
        let mut f=private_file(&self.dir.join(kind).join(format!("{}.jsonl",date_name(at))),true).map_err(|e|e.to_string())?;
        serde_json::to_writer(&mut f,value).map_err(|e|e.to_string())?;
        f.write_all(b"\n").map_err(|e|e.to_string())
    }
    fn event(&self, level:&str,message:String,channel:Option<&str>) {
        let at=now_unix();
        if let Err(e)=self.append("events",at,&Event{at,level:level.into(),message,channel:channel.map(str::to_owned)}) {*self.error.lock().unwrap()=Some(e);}
    }
    fn read_range(&self,kind:&str,from:u64,to:u64)->Result<Vec<Value>,String> {
        let _io=self.io.lock().unwrap();
        let mut day=from/86400*86400; let mut items=Vec::new();
        while day<to {
            let path=self.dir.join(kind).join(format!("{}.jsonl",date_name(day)));
            match std::fs::File::open(path) {
                Ok(file)=>for line in BufReader::new(file).lines() {
                    let line=line.map_err(|e|e.to_string())?;
                    // A partial final write after a crash must not erase other days' data.
                    if let Ok(value)=serde_json::from_str::<Value>(&line) {if value["at"].as_u64().is_some_and(|at|at>=from&&at<to){items.push(value);}}
                },
                Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
                Err(e)=>return Err(e.to_string()),
            }
            day+=86400;
        }
        items.sort_by_key(|v|v["at"].as_u64().unwrap_or(0));Ok(items)
    }
    fn prune(&self,now:u64) {
        let _io=self.io.lock().unwrap();
        for kind in ["metrics","events"] {
            if let Ok(entries)=std::fs::read_dir(self.dir.join(kind)) {for entry in entries.flatten(){let p=entry.path();if p.extension().and_then(|x|x.to_str())!=Some("jsonl"){continue;}if let Some(day)=p.file_stem().and_then(|x|x.to_str()).and_then(date_epoch){if day+86400<=now.saturating_sub(RETENTION){if let Err(e)=std::fs::remove_file(p){*self.error.lock().unwrap()=Some(e.to_string());}}}}}
        }
    }
    fn evaluate(&self,sample:&Value) -> Vec<String> {
        let cfg=self.cfg.lock().unwrap().clone();
        let now=sample["at"].as_u64().unwrap_or_else(now_unix);
        let used=sample["mem_total_kb"].as_f64().zip(sample["mem_avail_kb"].as_f64()).and_then(|(t,a)|percentage(t-a,t));
        let disk=sample["disk_used_kb"].as_f64().zip(sample["disk_total_kb"].as_f64()).and_then(|(u,t)|percentage(u,t));
        let mut state=self.state.lock().unwrap();let mut notices=Vec::new();
        for (key,label,value,limit) in [("cpu","CPU",sample["cpu_pct"].as_f64(),cfg.cpu_pct),("memory","内存",used,cfg.memory_pct),("disk","磁盘",disk,cfg.disk_pct)] {
            let rec=state.thresholds.entry(key.into()).or_default();
            // Missing samples or downtime break continuity; cooldown survives recovery/restart.
            if rec.last.is_some_and(|last|now.saturating_sub(last)>90 || now<last) {rec.since=None;}
            rec.last=Some(now);
            match value {
                Some(v) if v>limit=>{
                    let since=*rec.since.get_or_insert(now);
                    if now.saturating_sub(since)>=HOLD {
                        if !rec.active { self.event("warning",format!("{label} {v:.1}% 超过 {limit:.0}% 已持续 5 分钟"),None); }
                        rec.active=true;
                        if rec.last_event.is_none_or(|at|now.saturating_sub(at)>=COOLDOWN) {
                            rec.last_event=Some(now);notices.push(format!("{label} {v:.1}% > {limit:.0}%（持续 5 分钟）"));
                        }
                    }
                },
                Some(_)=>{if rec.active{self.event("recovery",format!("{label} 已恢复到阈值以内"),None);}rec.active=false;rec.since=None;},
                None=>{rec.since=None;rec.active=false;},
            }
        }
        if let Err(e)=save_json(&self.dir.join("alert-state.json"),&*state){*self.error.lock().unwrap()=Some(e);}
        notices
    }
    fn deliver(&self,title:&str,content:&str)->Result<(),String> {
        let token=self.token();if token.is_empty(){return Err("请先保存 PushPlus Token".into());}
        let agent=ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(12)).build();
        let result=(||{
            let response=agent.post("https://www.pushplus.plus/send").set("Content-Type","application/json")
                .send_string(&json!({"token":token,"title":title,"content":content,"template":"txt"}).to_string()).map_err(|_|"PushPlus 网络请求失败".to_string())?;
            let text=response.into_string().map_err(|_|"无法读取 PushPlus 响应".to_string())?;
            let value:Value=serde_json::from_str(&text).map_err(|_|"PushPlus 返回的不是 JSON".to_string())?;
            if value["code"].as_i64()!=Some(200)&&value["code"].as_str()!=Some("200") {return Err(format!("PushPlus 拒绝发送（code={}），请核对令牌、绑定和配额",value["code"]));}
            Ok(())
        })();
        self.event(if result.is_ok(){"notification"}else{"notification_error"},match &result{Ok(())=>format!("{title}：PushPlus 已接受发送请求（送达以客户端为准）"),Err(e)=>e.clone()},Some("pushplus"));result
    }
    pub fn start(self:&Arc<Self>,state:&Arc<State>) {
        let monitor=self.clone();let st=Arc::downgrade(state);
        std::thread::spawn(move||{
            let mut prev:Option<(u64,(u64,u64),(u64,u64))>=None;
            loop {
                let Some(st)=st.upgrade()else{return};
                let now=now_unix();let cpu=core::read_cpu_times();let net=core::read_net_totals();
                let(mut cpu_pct,mut rx,mut tx)=(None,None,None);
                if let(Some((last,old_cpu,old_net)),Some(cpu),Some(net))=(prev,cpu,net){let total=cpu.1.saturating_sub(old_cpu.1);if total>0{cpu_pct=Some((100.*(1.-cpu.0.saturating_sub(old_cpu.0) as f64/total as f64)).clamp(0.,100.));}let dt=now.saturating_sub(last).max(1)as f64;rx=Some(net.0.saturating_sub(old_net.0)as f64/dt);tx=Some(net.1.saturating_sub(old_net.1)as f64/dt);}
                if let(Some(cpu),Some(net))=(cpu,net){prev=Some((now,cpu,net));}
                let(t,a)=core::read_mem().unwrap_or((0,0));let(u,d)=core::disk_usage("/").unwrap_or((0,0));let(l1,l5,l15)=core::read_loadavg().unwrap_or((-1.,-1.,-1.));
                let sample=json!({"at":now,"cpu_pct":cpu_pct,"cores":core::cpu_count(),"mem_total_kb":t,"mem_avail_kb":a,"disk_used_kb":u,"disk_total_kb":d,"load1":l1,"load5":l5,"load15":l15,"rx_bps":rx,"tx_bps":tx,"panel_rss_kb":core::read_self_rss_kb().unwrap_or(0),"uptime_secs":core::read_uptime_secs().unwrap_or(0.)});
                *monitor.latest.lock().unwrap()=sample.clone();
                if let Err(e)=monitor.append("metrics",now,&sample){*monitor.error.lock().unwrap()=Some(e);}
                let notices=monitor.evaluate(&sample);
                if !notices.is_empty()&&monitor.cfg.lock().unwrap().pushplus_enabled {let m=monitor.clone();std::thread::spawn(move||{let _=m.deliver("Tunnel Panel 资源告警",&notices.join("；"));});}
                monitor.prune(now);drop(st);
                std::thread::sleep(Duration::from_secs(60));
            }
        });
    }
    pub fn handle(&self,mut req:Request,path:&str,method:&Method) {
        match (method,path) {
            (Method::Get,"/api/metrics/history")=>match range(&req) {
                Err(e)=>send_json(req,400,json!({"error":e})),
                Ok((from,to))=>match self.read_range("metrics",from,to) {Err(e)=>send_json(req,500,json!({"error":e})),Ok(mut items)=>{
                    let total=items.len();let step=total.div_ceil(1200).max(1);if step>1{items=items.into_iter().step_by(step).collect();}
                    send_json(req,200,json!({"samples":items,"from":from,"to":to,"downsampled":step>1,"total":total,"storage_error":self.error.lock().unwrap().clone()}));
                }},
            },
            (Method::Get,"/api/alerts")=>match range(&req) {
                Err(e)=>send_json(req,400,json!({"error":e})),
                Ok((from,to))=>match self.read_range("events",from,to){Err(e)=>send_json(req,500,json!({"error":e})),Ok(mut log)=>{
                    let total=log.len();let truncated=total>1000;if truncated{log.drain(0..total-1000);}
                    let cfg=self.cfg.lock().unwrap().clone();let state=self.state.lock().unwrap();
                    let active:Vec<_>=state.thresholds.iter().filter(|(_,v)|v.active).map(|(key,_)|key.clone()).collect();
                    send_json(req,200,json!({"thresholds":{"cpu_pct":cfg.cpu_pct,"memory_pct":cfg.memory_pct,"disk_pct":cfg.disk_pct,"duration_seconds":HOLD,"cooldown_seconds":COOLDOWN},"pushplus_enabled":cfg.pushplus_enabled,"pushplus_configured":!self.token().is_empty(),"channels":[{"id":"pushplus","label":"PushPlus","supported":true}],"active":active,"log":log,"total":total,"truncated":truncated,"from":from,"to":to,"storage_error":self.error.lock().unwrap().clone()}));
                }},
            },
            (Method::Post,"/api/alerts/config")=>{
                let body=read_body(&mut req);let input:Value=match serde_json::from_str(&body){Ok(v)=>v,Err(_)=>{send_json(req,400,json!({"error":"无效 JSON"}));return;}};
                let mut cfg=self.cfg.lock().unwrap();let mut next=cfg.clone();
                for (key,target) in [("cpu_pct",&mut next.cpu_pct),("memory_pct",&mut next.memory_pct),("disk_pct",&mut next.disk_pct)] {
                    if let Some(value)=input.get(key){let Some(n)=value.as_f64().filter(|v|v.is_finite()&&(1.0..=100.).contains(v))else{send_json(req,400,json!({"error":"阈值必须为 1–100%"}));return;};*target=n;}
                }
                if let Some(value)=input.get("pushplus_enabled"){let Some(b)=value.as_bool()else{send_json(req,400,json!({"error":"通知开关不合法"}));return;};next.pushplus_enabled=b;}
                let clear=input["clear_pushplus_token"].as_bool().unwrap_or(false);
                let replacement=input["pushplus_token"].as_str().unwrap_or("").trim();
                if replacement.len()>256 || replacement.chars().any(char::is_whitespace){send_json(req,400,json!({"error":"PushPlus Token 格式不合法"}));return;}
                let token=if clear{String::new()}else if !replacement.is_empty(){replacement.to_owned()}else{self.token()};
                if next.pushplus_enabled&&token.is_empty(){send_json(req,400,json!({"error":"启用通知前请填写 Token；清除 Token 时请先关闭通知"}));return;}
                let persist=(||{if clear {match std::fs::remove_file(self.dir.join("pushplus.token")){Ok(())=>{},Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(e.to_string())}}else if !replacement.is_empty(){private_file(&self.dir.join("pushplus.token"),false).and_then(|mut f|f.write_all(token.as_bytes())).map_err(|e|e.to_string())?;}save_json(&self.dir.join("alerts.json"),&next)})();
                match persist {Ok(())=>{let changed=cfg.cpu_pct!=next.cpu_pct||cfg.memory_pct!=next.memory_pct||cfg.disk_pct!=next.disk_pct;*cfg=next;if changed{for rec in self.state.lock().unwrap().thresholds.values_mut(){rec.since=None;rec.active=false;}}
                    self.event("config","告警设置已更新；资源阈值、持续 5 分钟与 1 小时冷却生效".into(),None);send_json(req,200,json!({"ok":true}));},Err(e)=>send_json(req,500,json!({"error":e}))}
            },
            (Method::Post,"/api/alerts/test")=>match self.deliver("Tunnel Panel 测试通知","这是一条手动测试消息，资源告警需连续超阈值 5 分钟。") {Ok(())=>send_json(req,200,json!({"ok":true})),Err(e)=>send_json(req,502,json!({"error":e}))},
            _=>send_json(req,404,json!({"error":"not found"})),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn isolated(name:&str)->(PathBuf,Arc<Monitor>){let dir=std::env::temp_dir().join(format!("cftp-monitor-{name}-{}-{}",std::process::id(),super::super::rand_hex(6)));std::fs::create_dir_all(&dir).unwrap();let m=Monitor::new(&dir.join("panel.json")).unwrap();(dir,m)}
    fn value(at:u64,cpu:f64)->Value{json!({"at":at,"cpu_pct":cpu,"mem_total_kb":100,"mem_avail_kb":50,"disk_total_kb":100,"disk_used_kb":20})}
    #[test]
    fn real_evaluator_requires_continuous_five_minutes_and_preserves_cooldown(){
        let(dir,m)=isolated("state");let start=now_unix();
        for minute in 0..5{assert!(m.evaluate(&value(start+minute*60,90.)).is_empty());}
        assert_eq!(m.evaluate(&value(start+300,90.)).len(),1);
        assert!(m.state.lock().unwrap().thresholds["cpu"].active);
        assert!(m.evaluate(&value(start+360,90.)).is_empty());
        m.evaluate(&value(start+420,10.));assert!(!m.state.lock().unwrap().thresholds["cpu"].active);
        for minute in 8..=14{assert!(m.evaluate(&value(start+minute*60,90.)).is_empty(),"recovery must not reset hourly cooldown");}
        let reopened=Monitor::new(&dir.join("panel.json")).unwrap();
        assert!(reopened.evaluate(&value(start+900,90.)).is_empty());
        assert!(reopened.evaluate(&value(start+4000,90.)).is_empty(),"downtime must break continuity");
        for minute in 1..5{assert!(reopened.evaluate(&value(start+4000+minute*60,90.)).is_empty());}
        assert_eq!(reopened.evaluate(&value(start+4300,90.)).len(),1);
        let log=reopened.read_range("events",start,start+5000).unwrap();assert!(log.iter().any(|e|e["level"]=="warning"));assert!(log.iter().any(|e|e["level"]=="recovery"));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn real_history_query_survives_restart_and_prunes_only_expired_buckets(){
        let(dir,m)=isolated("history");let now=now_unix();let t=now-86400;let sample=value(t,37.);
        m.append("metrics",t,&sample).unwrap();m.append("metrics",now,&value(now,42.)).unwrap();
        let old=now-92*86400;m.append("metrics",old,&value(old,99.)).unwrap();m.prune(now);
        assert!(!m.dir.join("metrics").join(format!("{}.jsonl",date_name(old))).exists());
        let reopened=Monitor::new(&dir.join("panel.json")).unwrap();let found=reopened.read_range("metrics",t,t+1).unwrap();assert_eq!(found.len(),1);assert_eq!(found[0]["cpu_pct"],37.);assert!(reopened.read_range("metrics",t+1,t+20).unwrap().is_empty());
        assert!(date_epoch("2026-02-30").is_none());assert_eq!(date_name(date_epoch("2024-02-29").unwrap()),"2024-02-29");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn alert_config_has_no_credential_and_invalid_sample_breaks_continuity(){
        let(dir,m)=isolated("missing");let now=now_unix();assert!(!serde_json::to_string(&AlertConfig::default()).unwrap().contains("token"));assert!(!m.cfg.lock().unwrap().pushplus_enabled);
        m.evaluate(&value(now,90.));m.evaluate(&json!({"at":now+60,"cpu_pct":null}));assert!(m.evaluate(&value(now+300,90.)).is_empty());assert!(!m.state.lock().unwrap().thresholds["cpu"].active);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
