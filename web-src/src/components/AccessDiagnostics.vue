<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Download, Loader2, Play, Square, X, Route, Laptop, Server, Trash2 } from 'lucide-vue-next';
import { api, type ConnectionSettings, type Optimization, type Rule } from '@/api';
import Button from '@/components/ui/Button.vue';
import Select from '@/components/ui/Select.vue';
import Modal from '@/components/ui/Modal.vue';
import RunComparison from '@/components/RunComparison.vue';
import { accessReports as runs, diagnosticUrl, milliseconds, summarize, newRunId, complete, comparable, type AccessRun, type AccessReport, type ProbeSample } from '@/lib/accessDiagnostics';

const props=defineProps<{rules:Rule[];connection:ConnectionSettings;running:boolean;external:boolean}>();
const emit=defineEmits<{close:[];settings:[];api:[];changed:[]}>();
const mode=ref<'browser'|'server'>('browser');
const selected=ref(props.rules.find(r=>r.enabled)?.hostname??'');
const path=ref('/');const profile=ref('web');const count=ref(3);const timeoutMs=ref(10000);
const network=ref('');const label=ref('');const ready=ref(false);const busy=ref(false);const error=ref('');const notice=ref('');const progress=ref('');
const probe=ref<HTMLIFrameElement>();const channel='cftp-access-probe-v1';let sequence=0,readyTimer=0;
let cancelled=false;let pending:{id:number;resolve:(s:ProbeSample)=>void;timer:number}|undefined;
let pauseTimer=0;let releasePause:(()=>void)|undefined;let serverAbort:AbortController|undefined;
const options=computed(()=>[{value:'*',label:'全部已启用规则'},...props.rules.map(r=>({value:r.hostname,label:r.hostname+(r.enabled?'':' · 已禁用')}))]);
const targets=computed(()=>props.rules.filter(r=>selected.value==='*'?r.enabled:r.hostname===selected.value));
const latest=computed(()=>runs.value.length?runs.value[runs.value.length-1]:undefined);
const shownRun=ref('');const displayed=computed(()=>runs.value.find(r=>r.id===shownRun.value)??latest.value);
const allReports=computed(()=>runs.value.flatMap(run=>run.results.map(report=>({run,report}))));
const comparisonTarget=ref('');const keys=computed(()=>[...new Set(allReports.value.map(({report:r})=>r.hostname+r.path))]);
const compareRows=computed(()=>{const target=comparisonTarget.value||keys.value[0];return allReports.value.filter(({report:r})=>r.hostname+r.path===target)});
const preview=ref(false);const applying=ref(false);const applied=ref('');const selectedPreset=ref('http2');const applyRestart=ref(false);
const cloudPrefix=ref('');const publicAck=ref(false);const plan=ref<Optimization|null>(null);const planText=ref('');
const diagnosis=computed(()=>{
  const run=displayed.value;if(!run)return '';
  const report=run.results[0];if(!report)return '';
  const stats=summarize(report.samples);
  if(!report.finished)return '本轮未完成，不能据此选线路。';
  if(stats.failed)return '存在超时或受限请求，先检查 DNS、证书、服务入口和网络；加缓存不能解决全部连接失败。';
  if(report.samples.some(s=>s.status!==null&&s.status>=400))return '检测到了 HTTP 错误。先处理源站或入口问题，再比较速度。';
  if(report.profile==='stream')return 'SSE 首先需要绕过边缘缓存，并检查源站/Nginx 及时 flush、关闭响应缓冲。本次仅测试响应头。';
  if(report.profile==='api')return '动态 API 以不缓存为基线，优先对比连接协议与应用处理耗时。';
  return stats.medianMs!==null&&stats.medianMs>1000?'响应头中位耗时超过 1 秒；先从同设备换网络重测，再看服务器内测，避免把访问线路问题误当成隧道配置问题。':'可保留本轮基线，切换网络或只修改一个连接选项后再次检测。';
});
function finish(sample:ProbeSample){if(!pending)return;clearTimeout(pending.timer);const done=pending.resolve;pending=undefined;done(sample)}
function receive(event:MessageEvent){
 if(event.source!==probe.value?.contentWindow||event.origin!==location.origin||event.data?.channel!==channel)return;
 const data=event.data;if(data.kind==='ready'){clearTimeout(readyTimer);ready.value=true;return}if(data.kind==='unavailable'){error.value=data.error;return}
 if(data.kind!=='result'||data.id!==pending?.id)return;
 finish({elapsedMs:Number.isFinite(data.elapsedMs)?data.elapsedMs:timeoutMs.value,received:data.received===true,status:typeof data.status==='number'?data.status:null,timing:data.timing??null,error:data.error});
}
function browserSample(url:string):Promise<ProbeSample>{return new Promise(resolve=>{const id=++sequence;pending={id,resolve,timer:window.setTimeout(()=>{probe.value?.contentWindow?.postMessage({channel,kind:'cancel'},location.origin);finish({elapsedMs:timeoutMs.value,received:false,status:null,timing:null,error:'探针超时，请检查浏览器连接'})},timeoutMs.value+2000)};probe.value?.contentWindow?.postMessage({channel,kind:'sample',id,url,timeoutMs:timeoutMs.value},location.origin)})}
async function serverSample(url:string):Promise<ProbeSample>{serverAbort=new AbortController();try{const data=await api.serverDiagnostic(url,timeoutMs.value,serverAbort.signal);return {elapsedMs:data.elapsed_ms,received:data.status!==null,status:data.status,timing:data.timing??null,error:data.error??undefined}}catch{return {elapsedMs:timeoutMs.value,received:false,status:null,timing:null,error:cancelled?'已取消':'服务器探测请求失败'}}finally{serverAbort=undefined}}
function pause(){return new Promise<void>(resolve=>{releasePause=resolve;pauseTimer=window.setTimeout(()=>{releasePause=undefined;resolve()},350)})}
function cancel(){cancelled=true;serverAbort?.abort();probe.value?.contentWindow?.postMessage({channel,kind:'cancel'},location.origin);finish({elapsedMs:0,received:false,status:null,timing:null,error:'已取消'});clearTimeout(pauseTimer);releasePause?.();releasePause=undefined}
onMounted(()=>{window.addEventListener('message',receive);readyTimer=window.setTimeout(()=>{if(!ready.value&&mode.value==='browser')error.value='浏览器探针准备超时，请关闭后重试。'},15000)});
onUnmounted(()=>{cancel();clearTimeout(readyTimer);window.removeEventListener('message',receive)});
async function run(){
 if(busy.value||mode.value==='browser'&&!ready.value)return;
 error.value='';notice.value='';let todo:{rule:Rule;url:string}[];
 try{todo=targets.value.map(rule=>({rule,url:diagnosticUrl(rule.hostname,path.value)}));if(!todo.length)throw new Error('没有可检测的规则');if(mode.value==='browser'&&!network.value.trim())throw new Error('先给当前网络起个名字，例如：家中 Wi-Fi、电信 5G。')}catch(e){error.value=(e as Error).message;return}
 const round:AccessRun={id:newRunId(),label:label.value.trim().slice(0,50)||'测试 '+(runs.value.length+1),network:mode.value==='browser'?network.value.trim().slice(0,50):'面板服务器出口',source:mode.value==='browser'?'current-device-browser':'panel-server',at:new Date().toISOString(),results:[]};
 runs.value.push(round);if(runs.value.length>30)runs.value.splice(0,runs.value.length-30);shownRun.value=round.id;
 // Access the reactive object, not the raw object passed to push.
 const current=runs.value[runs.value.length-1];cancelled=false;busy.value=true;
 try{for(const {rule,url} of todo){if(cancelled)break;current.results.push({runId:current.id,mode:mode.value,hostname:rule.hostname,path:path.value,url,profile:profile.value,at:new Date().toISOString(),samples:[],count:count.value,timeoutMs:timeoutMs.value,finished:false,connection:{protocol:props.connection.protocol,'edge-ip-version':props.connection['edge-ip-version'],region:props.connection.region}});const report=current.results[current.results.length-1];for(let i=0;i<count.value;i++){if(cancelled)break;progress.value=rule.hostname+' · '+(i+1)+' / '+count.value;const sample=mode.value==='browser'?await browserSample(url):await serverSample(url);if(cancelled)break;report.samples.push(sample);if(i+1<count.value)await pause()}report.finished=!cancelled&&report.samples.length===report.count}}
 finally{busy.value=false;progress.value=cancelled?'本轮已停止，未完成结果不排名。':'本轮完成。换网络后修改标签并开始新一轮。'}
}
function download(){const url=URL.createObjectURL(new Blob([JSON.stringify({version:2,exportedAt:new Date().toISOString(),runs:runs.value},null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='access-diagnostics.json';a.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000)}
function clear(){if(busy.value)return;runs.value=[];shownRun.value='';comparisonTarget.value='';notice.value='此浏览器中的测试记录已清空。'}
function proposeConnection(){
 if(!displayed.value?.results.some(complete)){error.value='先完成一轮测试，作为优化前的基线。';return}
 const settings={...props.connection,protocol:selectedPreset.value};
 if(settings.protocol===props.connection.protocol){notice.value='当前已使用该协议，无需重复保存。';return}
 plan.value={action:'connection',confirmed:true,settings,before:{...props.connection},restart:false};applyRestart.value=false;
 planText.value='协议 '+props.connection.protocol+' → '+settings.protocol+'；IP 版本、区域和日志级别保持现状。只影响面板主机到 Cloudflare 的连接。可仅保存，或确认短暂断线后立即重启应用。';preview.value=true;
}
function proposeBypass(){
 const report=displayed.value?.results.find(complete);
 if(!report){error.value='先完成一轮测试。';return}
 if(!['api','stream'].includes(report.profile)){error.value='静态资源请使用源站 Cache-Control 与已有 CDN 缓存；不自动强制缓存面板或用户内容。';return}
 cloudPrefix.value=report.path;publicAck.value=false;
 plan.value={action:'bypass',confirmed:true,hostname:report.hostname,prefix:report.path};
 planText.value='为 '+report.hostname+' 的指定路径前缀开启“绕过缓存”。这可避免 API/SSE 被错误缓存，可能增加回源；不会关闭源站缓冲、不会修改 DNS/SSL，也不保证延迟降低。';preview.value=true;
}
async function apply(){
 const draft=plan.value;if(!draft||applying.value)return;error.value='';
 if(draft.action==='bypass'&&(!publicAck.value||!cloudPrefix.value.startsWith('/')||cloudPrefix.value.startsWith('//'))){error.value='请检查路径前缀并确认影响范围。';return}
 applying.value=true;try{const result=await api.optimize({...draft,prefix:draft.action==='bypass'?cloudPrefix.value:undefined,restart:draft.action==='connection'?applyRestart.value:undefined});applied.value=result.output;notice.value=result.output;preview.value=false;emit('changed')}catch(e){error.value=(e as Error).message}finally{applying.value=false}
}
function previousStats(report:AccessReport){const prior=runs.value.filter(r=>r.id!==displayed.value?.id&&r.source===displayed.value?.source).flatMap(r=>r.results).filter(r=>comparable(report,r)&&complete(r));if(!prior.length||!complete(report))return null;const before=summarize(prior[prior.length-1].samples).medianMs;const after=summarize(report.samples).medianMs;return before&&after!==null?{before,after,change:(after/before-1)*100}:null}
</script>
<template>
 <div class="access-diagnostics space-y-5">
  <div class="flex items-start justify-between gap-3"><div><div class="eyebrow">DIAGNOSE · COMPARE · APPLY</div><h2 class="mt-2 text-xl font-semibold">访问诊断</h2><p class="mt-2 text-xs leading-6 text-muted-foreground">先选从哪里测，再为每轮网络命名；只比较同来源、同目标和同采样设置。</p></div><Button variant="ghost" size="icon" aria-label="关闭访问诊断" @click="emit('close')"><X class="h-4 w-4"/></Button></div>
  <div class="source-cards"><button type="button" :aria-pressed="mode==='browser'" :disabled="busy" @click="mode='browser'"><Laptop class="h-5 w-5"/><strong>当前设备浏览器</strong><span>你手里的手机/电脑 → 公网域名<br>切 Wi-Fi / 5G 可比较实际访问线路</span></button><button type="button" :aria-pressed="mode==='server'" :disabled="busy" @click="mode='server'"><Server class="h-5 w-5"/><strong>面板所在主机内部</strong><span>J1900 或 Windows 面板主机 → 公网域名<br>测服务器出口，不代表访客网络</span></button></div>
  <p class="info-strip !mb-0" role="status">当前：<strong>{{mode==='browser'?'此浏览器发出请求':'面板主机内部发出请求'}}</strong>。{{mode==='browser'?'跨域可能隐藏 HTTP 状态和分段计时。':'服务器不跟随重定向，返回真实 HTTP 状态；耗时不含浏览器到面板的往返。'}}</p>
  <div class="grid gap-4 sm:grid-cols-2"><label class="field-label">网络名称<input v-model.trim="network" :disabled="busy||mode==='server'" class="field-input" :placeholder="mode==='server'?'面板服务器出口':'例如：家中 Wi-Fi / 电信 5G'"/><span class="field-hint">{{mode==='server'?'服务器出口不会随你手机切换网络而改变。':'切换网络后改名，标签不会自动改变你的网络。'}}</span></label><label class="field-label">本轮名称<input v-model.trim="label" :disabled="busy" class="field-input" placeholder="例如：优化前 / HTTP2 方案"/></label><div class="field-label">公网域名<Select v-model="selected" :disabled="busy" label="诊断公网域名" :options="options"/></div><label class="field-label">公开只读路径<input v-model.trim="path" :disabled="busy" class="field-input" placeholder="/ 或 /health"/><span class="field-hint">只发匿名 GET，不携带登录 Cookie 或令牌。</span></label><div class="field-label">服务类型<Select v-model="profile" :disabled="busy" label="服务类型" :options="[{value:'web',label:'面板 / 网页'},{value:'static',label:'静态资源'},{value:'api',label:'动态 API'},{value:'stream',label:'SSE / 流式响应'}]"/></div><div class="grid grid-cols-2 gap-3"><div class="field-label">采样次数<Select v-model="count" :disabled="busy" label="采样次数" :options="[{value:3,label:'3 次'},{value:5,label:'5 次'}]"/></div><div class="field-label">单次超时<Select v-model="timeoutMs" :disabled="busy" label="单次超时" :options="[{value:10000,label:'10 秒'},{value:20000,label:'20 秒'}]"/></div></div></div>
  <div class="flex flex-wrap items-center gap-2"><Button v-if="!busy" :disabled="!targets.length||mode==='browser'&&!ready" @click="run"><Play class="h-4 w-4"/>开始新一轮</Button><Button v-else variant="outline" @click="cancel"><Square class="h-4 w-4"/>停止本轮</Button><Button variant="outline" :disabled="busy||!runs.length" @click="download"><Download class="h-4 w-4"/>导出轮次</Button><Button variant="ghost" :disabled="busy||!runs.length" @click="clear"><Trash2 class="h-4 w-4"/>清空记录</Button><Loader2 v-if="busy" class="h-4 w-4 animate-spin"/></div><p class="text-xs text-muted-foreground" role="status">{{progress||'此浏览器保留最近 30 轮，刷新和切换网络不丢记录。'}}</p>
  <p class="text-xs leading-6 text-muted-foreground">测量的是等待响应头，不是整页加载或 SSE 首事件。收到不透明响应可能实际为 4xx/5xx；DNS/TLS 为 0 也可能是连接复用。已有 Cloudflare 边缘，再加 CDN 不一定快。</p>
  <p v-if="error" class="error-strip" role="alert">{{error}}</p><p v-if="notice" class="info-strip" role="status">{{notice}}</p>
  <section v-if="runs.length" class="rounded-2xl border p-4"><h3 class="text-sm font-semibold">多网络 / 多轮对比</h3><div class="field-label mt-3">对比目标<Select :model-value="comparisonTarget||keys[0]" @update:model-value="comparisonTarget=$event" label="对比目标" :options="keys.map(value=>({value,label:value}))"/></div><RunComparison :rows="compareRows"/><p class="mt-2 text-xs leading-6 text-muted-foreground">图表把浏览器与服务器分组。仅完整且无失败的同路径、同类型、同采样设置可排名；服务器出口不能当作手机的更快线路。</p><div class="comparison-table"><table><thead><tr><th>轮次 / 网络</th><th>来源</th><th>中位数</th><th>完成度</th></tr></thead><tbody><tr v-for="row in compareRows" :key="row.run.id+row.report.url"><td>{{row.run.label}}<small>{{row.run.network}}</small></td><td>{{row.run.source==='current-device-browser'?'浏览器':'主机内部'}}</td><td>{{milliseconds(summarize(row.report.samples).medianMs)}}</td><td>{{complete(row.report)?'完整':'不可排名'}}</td></tr></tbody></table></div></section>
  <div v-if="runs.length" class="field-label">查看详细轮次<Select :model-value="displayed?.id??''" @update:model-value="shownRun=$event" label="查看轮次" :options="runs.map((run,i)=>({value:run.id,label:(i+1)+' · '+run.label+' · '+run.network}))"/></div>
  <section v-if="displayed" class="rounded-2xl border p-4"><h3 class="text-sm font-semibold">{{displayed.label}} · {{displayed.network}}</h3><p class="mt-1 text-xs text-muted-foreground">{{displayed.source==='current-device-browser'?'当前设备浏览器':'面板主机内部'}} · {{new Date(displayed.at).toLocaleString()}}</p><p class="mt-3 text-xs leading-6 text-muted-foreground">{{diagnosis}}</p><article v-for="report in displayed.results" :key="report.url" class="mt-4 border-t pt-4"><strong class="break-all text-xs">{{report.hostname}}{{report.path}}</strong><div class="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4"><div class="diagnostic-number"><span>收到响应</span><strong>{{summarize(report.samples).received}} / {{report.count}}</strong></div><div class="diagnostic-number"><span>中位耗时</span><strong>{{milliseconds(summarize(report.samples).medianMs)}}</strong></div><div class="diagnostic-number"><span>最小 / 最大</span><strong class="!text-xs">{{milliseconds(summarize(report.samples).minMs)}} / {{milliseconds(summarize(report.samples).maxMs)}}</strong></div><div class="diagnostic-number"><span>完成情况</span><strong class="!text-sm">{{complete(report)?'可比较':'不可排名'}}</strong></div></div><div v-for="(item,i) in report.samples" :key="i" class="mt-2 rounded-xl bg-muted/40 p-3 text-xs"><div class="flex flex-wrap justify-between gap-2"><span>第 {{i+1}} 次</span><span>{{item.received?milliseconds(item.elapsedMs):item.error}}</span></div><p class="mt-1.5 text-muted-foreground">HTTP {{item.status??'不可读取（跨域）'}}<template v-if="item.timing"> · DNS {{milliseconds(item.timing.dnsMs)}} · 连接 {{milliseconds(item.timing.connectMs)}} · TLS {{milliseconds(item.timing.tlsMs)}} · TTFB {{milliseconds(item.timing.ttfbMs)}} · {{item.timing.protocol||'未知协议'}}</template><template v-else> · 分段时间不可读取</template></p></div></article></section>
  <section v-if="displayed" class="rounded-2xl border bg-primary/5 p-4"><div class="flex items-center gap-2"><Route class="h-4 w-4 text-primary"/><h3 class="text-sm font-semibold">一键优化 · 先预览再应用</h3></div><p class="mt-2 text-xs leading-6 text-muted-foreground">不会声称一次测速能选出最快协议。保留基线、只改一项，再用同设备同网络复测。</p><div class="field-label mt-3">连接方案<Select v-model="selectedPreset" label="优化连接方案" :options="[{value:'http2',label:'HTTP/2 · 默认推荐'},{value:'auto',label:'自动 · 备选测试'},{value:'quic',label:'QUIC · 备选测试'}]"/></div><div class="mt-3 flex flex-wrap gap-2"><Button variant="outline" :disabled="busy||applying" @click="proposeConnection">一键应用连接方案</Button><Button variant="outline" :disabled="busy||applying" @click="proposeBypass">一键优化 API / SSE 缓存</Button></div></section>
  <div class="flex flex-wrap gap-2"><Button variant="outline" :disabled="busy" @click="emit('settings')">打开连接设置</Button><Button variant="outline" :disabled="busy" @click="emit('api')">打开 API / SSE 高级设置</Button></div>
  <iframe ref="probe" src="/api/diagnostics/probe" title="当前设备访问探针" class="hidden" aria-hidden="true" tabindex="-1"/>
  <Modal v-model="preview" label="确认优化方案" :busy="applying"><h2 class="text-lg font-semibold">确认优化方案</h2><p class="mt-3 text-sm leading-7">{{planText}}</p><template v-if="plan?.action==='connection'"><label class="switch-row mt-4 rounded-xl bg-muted/40 p-3"><span class="text-xs">保存并立即重启（会短暂断线）</span><input v-model="applyRestart" type="checkbox" class="switch-input" :disabled="!running||external"/></label><p class="mt-2 text-xs text-muted-foreground">{{external?'连接器由外部管理，只能保存后手动应用。':running?'当前连接器正在运行。':'连接器未运行；仅保存，下次启动生效。'}}</p></template><template v-else><label class="field-label mt-4">应用路径前缀<input v-model="cloudPrefix" class="field-input"/></label><label class="switch-row mt-3"><span class="text-xs leading-6">我确认只对上述 API/SSE 范围绕过缓存；/ 表示整个子域，可能增加回源。</span><input v-model="publicAck" type="checkbox" class="switch-input"/></label></template><p v-if="error" class="error-strip mt-4">{{error}}</p><div class="mt-5 flex justify-end gap-2"><Button variant="outline" :disabled="applying" @click="preview=false">取消</Button><Button :disabled="applying||plan?.action==='bypass'&&!publicAck" @click="apply"><Loader2 v-if="applying" class="h-4 w-4 animate-spin"/>确认应用</Button></div></Modal>
 </div>
</template>
