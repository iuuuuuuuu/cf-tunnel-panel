<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { BellRing, ChartNoAxesCombined, CircleAlert, Loader2, Send, CheckCircle2, RefreshCw, KeyRound } from 'lucide-vue-next';
import { api, type AlertSettings, type MetricsSample } from '@/api';
import Button from '@/components/ui/Button.vue';
import Select from '@/components/ui/Select.vue';
import Modal from '@/components/ui/Modal.vue';
import MetricChart from '@/components/MetricChart.vue';
const emit=defineEmits<{notice:[text:string,bad?:boolean]}>();
const period=ref('day'),from=ref(''),to=ref('');
const samples=ref<MetricsSample[]>([]),alerts=ref<AlertSettings|null>(null);
const cpuLimit=ref(85),memoryLimit=ref(90),diskLimit=ref(90),enabled=ref(false),token=ref('');
const loading=ref(false),saving=ref(false),testing=ref(false),clearConfirm=ref(false);
const error=ref(''),message=ref(''),storageError=ref('');const total=ref(0),downsampled=ref(false);
let timer=0;let generation=0;
const localDate=(date:Date)=>new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,10);
const today=computed(()=>localDate(new Date()));
function selectedRange(){const end=new Date();end.setHours(0,0,0,0);end.setDate(end.getDate()+1);const start=new Date();start.setHours(0,0,0,0);if(period.value==='week')start.setDate(start.getDate()-6);if(period.value==='month')start.setDate(start.getDate()-29);if(period.value==='custom'){if(!from.value||!to.value)throw new Error('请选择开始与结束日期');const a=new Date(from.value+'T00:00:00'),b=new Date(to.value+'T00:00:00');b.setDate(b.getDate()+1);if(!Number.isFinite(a.getTime())||!Number.isFinite(b.getTime())||b<=a)throw new Error('日期范围不合法');return {from:String(Math.floor(a.getTime()/1000)),to:String(Math.floor(b.getTime()/1000))}}return {from:String(Math.floor(start.getTime()/1000)),to:String(Math.floor(end.getTime()/1000))}}
const logs=computed(()=>[...(alerts.value?.log??[])].reverse());
const activeNames=computed(()=>alerts.value?.active.map(key=>({cpu:'CPU',memory:'内存',disk:'磁盘'}[key]??key)).join('、')??'');
const eventLabel=(level:string)=>({warning:'超限',recovery:'已恢复',notification:'通知已受理',notification_error:'通知失败',config:'配置变更'}[level]??level);
async function load(refreshConfig=false){const id=++generation;error.value='';loading.value=true;try{const range=selectedRange();const [history,settings]=await Promise.all([api.metricHistory(range.from,range.to),api.alerts(range.from,range.to)]);if(id!==generation)return;samples.value=history.samples;total.value=history.total;downsampled.value=history.downsampled;storageError.value=history.storage_error||settings.storage_error||'';if(refreshConfig||!alerts.value){cpuLimit.value=settings.thresholds.cpu_pct;memoryLimit.value=settings.thresholds.memory_pct;diskLimit.value=settings.thresholds.disk_pct;enabled.value=settings.pushplus_enabled}alerts.value=settings}catch(e){if(id===generation)error.value=(e as Error).message}finally{if(id===generation)loading.value=false}}
async function save(){saving.value=true;error.value='';message.value='';try{await api.saveAlerts({cpu_pct:cpuLimit.value,memory_pct:memoryLimit.value,disk_pct:diskLimit.value,pushplus_enabled:enabled.value,pushplus_token:token.value});token.value='';emit('notice','告警设置已保存：连续 5 分钟超限触发，同一指标每小时最多通知一次。');await load(true)}catch(e){error.value=(e as Error).message;emit('notice',error.value,true)}finally{saving.value=false}}
async function clear(){saving.value=true;try{await api.saveAlerts({cpu_pct:cpuLimit.value,memory_pct:memoryLimit.value,disk_pct:diskLimit.value,pushplus_enabled:false,pushplus_token:'',clear_pushplus_token:true});enabled.value=false;token.value='';clearConfirm.value=false;emit('notice','已清除 PushPlus Token，并关闭通知。');await load(true)}catch(e){error.value=(e as Error).message;emit('notice',error.value,true)}finally{saving.value=false}}
async function test(){testing.value=true;error.value='';message.value='';try{await api.testAlert();emit('notice','PushPlus 已接受测试通知；请在接收端确认是否收到。');await load()}catch(e){const text=(e as Error).message;await load();error.value=text;emit('notice',text,true)}finally{testing.value=false}}
onMounted(()=>{load(true);timer=window.setInterval(()=>{if(!loading.value)load()},60000)});onUnmounted(()=>{clearInterval(timer);generation++});
</script>
<template>
 <div class="monitor-center space-y-5">
  <div v-if="activeNames" class="error-strip flex items-start gap-3" role="alert"><CircleAlert class="mt-0.5 h-5 w-5 shrink-0"/><div><strong>资源告警：{{activeNames}}</strong><p class="mt-1 text-xs">已持续超限至少 5 分钟；恢复后会在日志记录。</p></div></div>
  <div v-if="storageError" class="error-strip" role="alert">记录写入或读取异常：{{storageError}}。请检查磁盘空间和配置目录权限。</div>
  <p v-if="error" class="error-strip" role="alert">{{error}}</p><p v-if="message" class="info-strip" role="status">{{message}}</p>
  <section class="settings-card space-y-4"><div class="section-heading !mb-0"><div><div class="eyebrow">HOST HISTORY</div><h2>运行历史</h2><p>主机后台每分钟记录，关闭网页也继续；保留最近 90 天。日期按当前设备时区筛选。</p></div><Button variant="outline" :disabled="loading" @click="load()"><RefreshCw class="h-4 w-4" :class="{'animate-spin':loading}"/>刷新记录</Button></div>
   <div class="flex flex-wrap items-end gap-3"><div class="field-label min-w-[150px]">查看周期<Select v-model="period" label="查看监控周期" :disabled="loading" :options="[{value:'day',label:'今天'},{value:'week',label:'最近 7 天'},{value:'month',label:'最近 30 天'},{value:'custom',label:'自定义范围'}]"/></div><label v-if="period==='custom'" class="field-label">开始日期<input v-model="from" type="date" class="field-input" :max="to||today"/></label><label v-if="period==='custom'" class="field-label">结束日期<input v-model="to" type="date" class="field-input" :min="from" :max="today"/></label><Button variant="outline" :disabled="loading" @click="load()">应用范围</Button><span class="text-xs text-muted-foreground">{{total}} 条真实记录{{downsampled?' · 图表显示抽样点，原始分钟记录仍保留':''}}</span></div>
   <div class="chart-panel"><div class="chart-title"><ChartNoAxesCombined class="h-4 w-4 text-primary"/>CPU / 内存 / 系统磁盘</div><MetricChart :samples="samples" mode="percent"/></div>
   <div class="chart-panel"><div class="chart-title"><ChartNoAxesCombined class="h-4 w-4 text-primary"/>上下行流量</div><MetricChart :samples="samples" mode="network"/></div>
  </section>
  <section class="settings-card"><div class="section-heading"><div><div class="eyebrow">ALERT RULES</div><h2>资源告警 · 推荐值已填好</h2><p>连续超限 5 分钟才触发，同一指标每小时最多通知一次。初次启用后，等待积累足够数据。</p></div><BellRing class="h-5 w-5 text-primary"/></div>
   <div class="grid gap-4 sm:grid-cols-3"><label class="field-label">CPU 超过 (%)<input v-model.number="cpuLimit" class="field-input" type="number" min="1" max="100"/></label><label class="field-label">内存超过 (%)<input v-model.number="memoryLimit" class="field-input" type="number" min="1" max="100"/></label><label class="field-label">磁盘超过 (%)<input v-model.number="diskLimit" class="field-input" type="number" min="1" max="100"/></label></div>
   <div class="info-strip mt-4">不开启通知也会记录超限和恢复日志。建议先保留 CPU 85% / 内存 90% / 磁盘 90%，再根据长期图表调整。</div>
   <div class="rounded-2xl border p-4"><div class="flex flex-wrap items-center justify-between gap-3"><div><h3 class="text-sm font-semibold">通知渠道</h3><p class="mt-1 text-xs text-muted-foreground">首个渠道支持 PushPlus；其他渠道按相同接口扩展。</p></div><Select label="通知渠道" model-value="pushplus" :options="[{value:'pushplus',label:'PushPlus'}]"/></div>
    <ol class="mt-4 list-decimal space-y-2 pl-4 text-xs leading-6 text-muted-foreground"><li>在 PushPlus 登录并绑定接收方式，复制个人 Token。</li><li>填写下方 Token，打开通知开关并保存。</li><li>点“发送测试通知”，在手机接收端确认送达。</li></ol>
    <label class="field-label mt-4">PushPlus Token<input v-model.trim="token" class="field-input" type="password" autocomplete="new-password" :placeholder="alerts?.pushplus_configured?'已配置；留空保持，填新值替换':'粘贴 PushPlus 个人 Token'"/><span class="field-hint">只保存到面板所在主机的 monitoring/pushplus.token；接口不回显。Linux 权限 0600。</span></label>
    <label class="switch-row mt-4 rounded-xl bg-muted/40 p-3"><span><strong class="block text-sm">启用 PushPlus 通知</strong><small class="mt-1 block text-xs text-muted-foreground">默认关闭；手动测试通知不受开关影响。</small></span><input v-model="enabled" class="switch-input" type="checkbox" aria-label="启用 PushPlus 通知"/></label>
    <div class="mt-4 flex flex-wrap gap-2"><Button :disabled="saving||loading" @click="save"><Loader2 v-if="saving" class="h-4 w-4 animate-spin"/>保存告警设置</Button><Button variant="outline" :disabled="testing||saving||!alerts?.pushplus_configured" @click="test"><Send class="h-4 w-4"/>{{testing?'发送中…':'发送测试通知'}}</Button><Button v-if="alerts?.pushplus_configured" variant="ghost" :disabled="saving" @click="clearConfirm=true"><KeyRound class="h-4 w-4"/>清除令牌</Button></div>
   </div>
  </section>
  <section class="settings-card"><div class="section-heading"><div><div class="eyebrow">EVENT HISTORY</div><h2>告警与通知日志</h2><p>跟随上方日期范围；包含超限、恢复、设置变更和发送结果。</p></div><span class="text-xs text-muted-foreground">{{alerts?.total??0}} 条{{alerts?.truncated?' · 显示最近 1,000 条':''}}</span></div><p v-if="!logs.length" class="info-strip !mb-0">所选周期暂无事件；历史采样仍在后台继续。</p><div v-else class="alert-log"><article v-for="(event,i) in logs" :key="event.at+'-'+i" class="alert-entry"><time>{{new Date(event.at*1000).toLocaleString()}}</time><span :class="{'!text-primary':event.level==='recovery'||event.level==='notification'}">{{eventLabel(event.level)}}</span><strong>{{event.message}}</strong></article></div></section>
  <Modal v-model="clearConfirm" label="清除 PushPlus 令牌" :busy="saving"><h2 class="text-lg font-semibold">清除 PushPlus 令牌？</h2><p class="mt-3 text-sm text-muted-foreground">删除主机上的令牌文件并关闭通知；监控与本地日志继续保留。</p><div class="mt-5 flex justify-end gap-2"><Button variant="outline" :disabled="saving" @click="clearConfirm=false">取消</Button><Button :disabled="saving" @click="clear">确认清除</Button></div></Modal>
 </div>
</template>
