<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { api, type Rule } from '@/api';
import Button from '@/components/ui/Button.vue';
import Select from '@/components/ui/Select.vue';
import Switch from '@/components/ui/Switch.vue';
import { ArrowUpRight, Copy, Download, CloudUpload, BookOpen } from 'lucide-vue-next';
const props = defineProps<{rules: Rule[]; hasToken: boolean}>();
const emit = defineEmits<{notice: [message: string, bad?: boolean]; token: []}>();
const hostname = defineModel<string>('hostname', { default: '' });
const hostOptions = computed(() => props.rules.map(rule => ({value: rule.hostname, label: rule.hostname + (rule.note ? ' · ' + rule.note : '') + (rule.enabled ? '' : ' · 已禁用')})));
const selectedRule = computed(() => props.rules.find(rule => rule.hostname === hostname.value));
const zoneAdvanced = ref(false);
watch(() => props.rules.map(rule => rule.hostname), hosts => {
  if (!hosts.includes(hostname.value)) hostname.value = hosts[0] || '';
}, { immediate: true });
function resetScope(){
  prefix.value='/'; requestBuffer.value='';responseBuffer.value='';scopedRocket.value='';acknowledge.value=false;
  const service=props.rules.find(rule=>rule.hostname===hostname.value)?.service || '';
  try {const target=new URL(service);upstream.value=target.host||'127.0.0.1:8080';}catch{upstream.value='127.0.0.1:8080';}
}
const prefix = ref('/');
const upstream = ref('127.0.0.1:8080');
const busy = ref(false);
const error = ref('');
const result = ref('');
const zone = ref('');
const settings = ref<Record<string, {value: string; editable: boolean}>>({});
const pending = ref<{setting: string; value: string} | null>(null);
const ssl = ref('strict');
const https = ref('on');
const rocket = ref('off');
const requestBuffer = ref('');
const responseBuffer = ref('');
const scopedRocket = ref('');
const acknowledge = ref(false);
const configParams = computed(() => ({...(requestBuffer.value ? {request_body_buffering:requestBuffer.value} : {}), ...(responseBuffer.value ? {response_body_buffering:responseBuffer.value} : {}), ...(scopedRocket.value ? {rocket_loader:scopedRocket.value === 'on'} : {})}));
const configJson = computed(() => JSON.stringify({description:'API configuration', expression:expression.value, action:'set_config', action_parameters:configParams.value, enabled:true}, null, 2));
const disablesInspection = computed(() => requestBuffer.value === 'none' || responseBuffer.value === 'none');
watch([hostname, prefix, requestBuffer, responseBuffer], () => acknowledge.value = false);
watch(hostname, () => {zone.value = ''; settings.value = {}; pending.value = null; error.value = ''; result.value = ''; resetScope();});
resetScope();
const valid = computed(() => /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]+$/i.test(hostname.value) && prefix.value.startsWith('/') && !/[\r\n]/.test(prefix.value));
const expression = computed(() => `(http.host eq ${JSON.stringify(hostname.value.toLowerCase())} and starts_with(http.request.uri.path, ${JSON.stringify(prefix.value)}))`);
const cacheJson = computed(() => JSON.stringify({description:'API cache bypass', expression:expression.value, action:'set_cache_settings', action_parameters:{cache:false}, enabled:true}, null, 2));
const nginx = computed(() => `# 在现有 Nginx server 内添加；SSE Content-Type 由应用返回。\nlocation ${/^\/[a-zA-Z0-9/_-]*$/.test(prefix.value) ? prefix.value : '/api/'} {\n    proxy_pass http://${/^[a-zA-Z0-9.\-]+:\d+$/.test(upstream.value) ? upstream.value : '127.0.0.1:8080'};\n    proxy_http_version 1.1;\n    proxy_set_header Connection "";\n    proxy_set_header Host $host;\n    proxy_buffering off;\n    proxy_request_buffering off;\n    proxy_cache off;\n    proxy_read_timeout 300s;\n    add_header Cache-Control "no-cache, no-transform" always;\n    add_header X-Accel-Buffering "no" always;\n}`);
async function cloud(action: string, extra: Record<string,string> = {}) {
  if (busy.value) return;
  busy.value = true; error.value = ''; result.value = '';
  const target = hostname.value;
  try {
    const response = await api.cloud({action,hostname:target,prefix:prefix.value,...extra});
    if (hostname.value !== target) return;
    if (action === 'read') {
      zone.value = response.zone || ''; settings.value = response.settings || {};
      ssl.value = settings.value.ssl?.value || 'strict'; https.value = settings.value.always_use_https?.value || 'off'; rocket.value = settings.value.rocket_loader?.value || 'off';
      emit('notice', '已读取整个 ' + zone.value + ' 的设置（包含所有子域）');
    } else {
      if (action === 'setting' && settings.value[extra.setting]) settings.value[extra.setting].value = extra.value;
      result.value = action === 'cache' ? '缓存绕过规则已保存到 Cloudflare。请在云端核对后续规则是否覆盖此规则。' : action === 'configuration' ? 'Cloudflare 已确认缓冲 / 页面优化规则保存成功。' : 'Cloudflare 已确认设置更新。';
      pending.value = null; emit('notice', result.value);
    }
  } catch (e: any) { error.value = e.message; emit('notice', error.value, true); }
  finally { busy.value = false; }
}
async function copy(text: string) {
  try {
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
    else { const el = document.createElement('textarea'); el.value = text; document.body.appendChild(el); el.select(); const ok = document.execCommand('copy'); el.remove(); if (!ok) throw new Error(); }
    emit('notice', '已复制配置');
  } catch { emit('notice', '复制失败，请选中配置手动复制', true); }
}
function download() {
  const url = URL.createObjectURL(new Blob([cacheJson.value], {type:'application/json'}));
  const a = document.createElement('a'); a.href=url; a.download='api-cache-rule.json'; a.click(); URL.revokeObjectURL(url);
}
</script>
<template>
  <div class="space-y-5">
    <section class="settings-card domain-scope" aria-label="API 配置作用范围">
      <div class="section-heading"><div><div class="eyebrow">PER DOMAIN · NOT GLOBAL</div><h2>先选要配置的公网域名</h2><p>缓存绕过、请求/响应缓冲和路径 Rocket Loader，只作用于选中的域名 + 路径前缀，不是所有转发规则的通用设置。</p></div></div>
      <div class="grid gap-4 sm:grid-cols-2"><div class="field-label">快捷选择转发域名<Select v-model="hostname" label="快捷选择转发域名" :disabled="busy || !rules.length" :options="hostOptions"/><span class="field-hint">也可在总览每条规则的“API / 流式”按钮直接进入。</span></div><label class="field-label">路径前缀<input v-model="prefix" :disabled="busy" class="field-input" placeholder="/api/"/><span class="field-hint">/ 表示此子域全部路径；/api/ 仅匹配该前缀，不影响其他子域。</span></label></div>
      <div class="scope-banner mt-4" role="status"><strong class="break-all">{{ hostname || '请先添加转发规则' }}{{ prefix }}</strong><p>当前子域范围 · 缓存与流式规则写入 Cloudflare 云端；不是修改 cloudflared 的全局配置。</p><p v-if="selectedRule?.note">备注：{{ selectedRule.note }}</p></div>
      <p v-if="!rules.length" class="mt-3 text-xs text-muted-foreground">暂无转发域名，请先回总览添加规则。</p>
    </section>
    <section class="settings-card">
      <div class="section-heading"><div><div class="eyebrow">EDGE RULES</div><h2>当前子域 · API 缓存策略</h2><p>按域名与路径前缀匹配，绕过边缘缓存。</p></div><CloudUpload class="h-5 w-5 text-muted-foreground" /></div>
      <p class="text-xs leading-6 text-muted-foreground">仅对 <strong class="break-all text-foreground">{{hostname}}{{prefix}}</strong> 绕过缓存。不会修改其他子域；动态 API / SSE 可按实际路径配置，不保证固定提速。</p>
      <div class="mt-5 rounded-lg border bg-muted/30 p-4"><div class="mb-2 text-xs font-medium text-muted-foreground">规则表达式 · 即将应用的范围</div><code class="break-all text-xs">{{ expression }}</code></div>
      <div class="mt-4 flex flex-wrap gap-2"><Button :disabled="busy || !valid || !hasToken" @click="cloud('cache')"><CloudUpload class="h-4 w-4" />{{ busy ? '请求中…' : '应用缓存绕过规则' }}</Button><Button variant="outline" :disabled="!valid" @click="download"><Download class="h-4 w-4" />导出规则 JSON</Button><Button v-if="!hasToken" variant="outline" @click="emit('token')">配置 API Token</Button></div>
      <p class="mt-3 text-xs leading-relaxed text-muted-foreground">应用会新增或更新面板创建的同范围 Cache Rule，保留其他规则。需要 Zone Read 和 Cache Rules Edit 权限；套餐或权限不足时会显示 Cloudflare 原始错误。</p>
      <details class="advanced-section mt-4"><summary>查看规则 JSON</summary><pre class="code-block mt-3">{{ cacheJson }}</pre></details>
    </section>
    <section class="settings-card">
      <div class="section-heading"><div><div class="eyebrow">CONFIGURATION RULES</div><h2>当前子域 · 请求与响应缓冲</h2><p>仅应用到 {{hostname}}{{prefix}}，单独创建 Configuration Rule；不是整个 Zone 的设置。</p></div></div>
      <div class="grid gap-4 sm:grid-cols-3">
        <div class="field-label">请求体缓冲<Select v-model="requestBuffer" label="请求体缓冲" :disabled="busy" :options="[{value:'',label:'不覆盖'},{value:'standard',label:'Standard · 默认检查'},{value:'full',label:'Full · 完整缓冲'},{value:'none',label:'None · 不缓冲'}]" /></div>
        <div class="field-label">响应体缓冲<Select v-model="responseBuffer" label="响应体缓冲" :disabled="busy" :options="[{value:'',label:'不覆盖'},{value:'standard',label:'Standard · 默认检查'},{value:'none',label:'None · 不缓冲'}]" /></div>
        <div class="field-label">Rocket Loader（仅匹配路径）<Select v-model="scopedRocket" label="路径 Rocket Loader" :disabled="busy" :options="[{value:'',label:'不覆盖'},{value:'off',label:'关闭'},{value:'on',label:'开启'}]" /></div>
      </div>
      <div v-if="disablesInspection" class="info-strip mt-4"><Switch v-model="acknowledge" label="我了解关闭缓冲会影响报文检查" description="None 会绕过依赖对应报文体检查的功能，可能影响 WAF 和其他安全检测。请仅应用到已鉴权的 API 路径。" /></div>
      <div class="mt-4 flex flex-wrap gap-2"><Button :disabled="busy || !valid || !hasToken || !Object.keys(configParams).length || (disablesInspection && !acknowledge)" @click="cloud('configuration', {request:requestBuffer,response:responseBuffer,rocket:scopedRocket})"><CloudUpload class="h-4 w-4" />应用缓冲与页面规则</Button><Button variant="outline" :disabled="!valid || !Object.keys(configParams).length" @click="copy(configJson)"><Copy class="h-4 w-4" />复制规则 JSON</Button></div>
      <p class="mt-3 text-xs leading-relaxed text-muted-foreground">需要 Config Settings Write 权限。仅覆盖选中的参数；更新同范围面板规则时会替换该规则的参数。“不覆盖”表示从本条规则中移除该设置。能力及配额以账户返回为准。</p>
      <details class="advanced-section mt-4"><summary>查看配置规则 JSON</summary><pre class="code-block mt-3">{{ configJson }}</pre></details>
    </section>
    <section class="settings-card zone-settings" aria-label="整个域名区域的高级设置">
      <div class="section-heading"><div><div class="eyebrow">WHOLE ZONE · ADVANCED</div><h2>整个域名区域 · HTTPS 与页面优化</h2><p>这里不是单个子域设置。SSL / 强制 HTTPS / 全局 Rocket Loader 会影响当前域名所属 Zone 的所有子域，路径前缀不限制它们。</p></div></div>
      <Button variant="outline" :aria-expanded="zoneAdvanced" @click="zoneAdvanced = !zoneAdvanced">{{zoneAdvanced ? '收起整个 Zone 高级设置' : '了解影响，展开整个 Zone 设置'}}</Button>
      <div v-if="zoneAdvanced" class="mt-4 space-y-4">
      <div class="scope-warning"><strong>注意：整个 Zone 生效，不是只对 {{hostname}}。</strong><p>先读取真实 Zone 名称；修改前再次确认。不要为了一个子域的 API 需求去关闭整个 Zone 的安全设置。</p></div>
      <Button variant="outline" :disabled="busy || !valid || !hasToken" @click="cloud('read')">读取整个 Zone 设置</Button>
      <div v-if="!zone" class="info-strip">通过所选子域查找它所属的整个 Zone。需要 Zone Read 和 Zone Settings Read / Edit 权限。</div>
      <template v-else>
        <div class="info-strip">作用范围：整个 {{ zone }} 域名区域，包含所有子域。此处的 SSL 模式不能替代 Tunnel 的 HTTPS 回源与证书校验设置。</div>
        <div class="space-y-4">
          <div class="cloud-setting"><div><h3>SSL / TLS 模式</h3><p>建议优先 Full (strict)，源站须有有效证书。Full 会放宽证书校验。</p></div><Select v-model="ssl" label="SSL 模式" :options="[{value:'strict',label:'Full (strict)'},{value:'full',label:'Full'},{value:'flexible',label:'Flexible'},{value:'off',label:'Off'}]" /><Button variant="outline" :disabled="busy || !settings.ssl?.editable || ssl === settings.ssl?.value" @click="pending = {setting:'ssl',value:ssl}">预览变更</Button></div>
          <div class="cloud-setting"><div><h3>始终使用 HTTPS</h3><p>将访客的 HTTP 请求重定向到 HTTPS。</p></div><Select v-model="https" label="始终使用 HTTPS" :options="[{value:'on',label:'开启'},{value:'off',label:'关闭'}]" /><Button variant="outline" :disabled="busy || !settings.always_use_https?.editable || https === settings.always_use_https?.value" @click="pending = {setting:'always_use_https',value:https}">预览变更</Button></div>
          <div class="cloud-setting"><div><h3>Rocket Loader</h3><p>优化网页脚本加载；API 请求通常不需要。</p></div><Select v-model="rocket" label="Rocket Loader" :options="[{value:'on',label:'开启'},{value:'off',label:'关闭'}]" /><Button variant="outline" :disabled="busy || !settings.rocket_loader?.editable || rocket === settings.rocket_loader?.value" @click="pending = {setting:'rocket_loader',value:rocket}">预览变更</Button></div>
        </div>
        <div v-if="pending" class="mt-5 rounded-lg border p-4"><p class="text-sm">更新 {{ zone }} 的 <strong>{{ pending.setting }}</strong>：{{ settings[pending.setting]?.value }} → <strong>{{ pending.value }}</strong></p><div class="mt-3 flex gap-2"><Button :disabled="busy" @click="cloud('setting', pending!)">确认应用到整个 Zone</Button><Button variant="outline" :disabled="busy" @click="pending = null">取消</Button></div></div>
      </template>
      </div>
    </section>
    <div v-if="error" role="alert" class="error-strip">{{ error }}</div><div v-if="result" role="status" class="info-strip">{{ result }}</div>
    <section class="settings-card">
      <div class="section-heading"><div><div class="eyebrow">ORIGIN · SSE</div><h2>当前子域 · 源站流式响应模板</h2><p>{{hostname}}{{prefix}}：以下为可复用模板，需复制到对应源站 Nginx；不会自动应用到任何域名。</p></div><BookOpen class="h-5 w-5 text-muted-foreground" /></div>
      <div class="grid gap-5 xl:grid-cols-2"><div class="space-y-4"><div class="info-strip">应用应返回 Content-Type: text/event-stream，并逐段 flush。Cache-Control: no-cache, no-transform 可用于流式响应。HTTP/2 不使用 Connection: keep-alive 头。</div><label class="field-label">Nginx 后面的 HTTP 服务<input v-model.trim="upstream" class="field-input" placeholder="127.0.0.1:8080" /></label><p class="text-xs leading-relaxed text-muted-foreground">右侧模板需要部署在你自己的 Nginx；面板不会改写应用响应头。proxy_request_buffering off 只控制该 Nginx 的请求缓冲，不代表关闭 Cloudflare 边缘缓冲。</p><Button variant="outline" @click="copy(nginx)"><Copy class="h-4 w-4" />复制 Nginx 模板</Button></div><pre class="code-block">{{ nginx }}</pre></div>
    </section>
    <section class="settings-card">
      <div class="section-heading"><div><div class="eyebrow">BEFORE YOU TUNE</div><h2>配置边界与排查</h2></div></div>
      <div class="guide-grid">
        <article><h3>缓冲配置按范围生效</h3><p>请求与响应缓冲是 Cloudflare 云端规则，不是 cloudflared 的 YAML 参数。Standard 不等同于完整缓冲；关闭后需要实测收益并检查安全策略影响。</p></article>
        <article><h3>QUIC 与 HTTP/2 都需要实测</h3><p>按网络丢包情况比较两种协议。全局区域会自动选边缘，重启不保证换到亚洲；cf-ray 表示处理该请求的边缘，不等于连接器节点。</p></article>
        <article><h3>不自动关闭安全保护</h3><p>WAF、挑战与 Bot 策略请按精确的 API 路径和鉴权条件调整。避免为降低延迟直接关闭整个域名的保护。</p></article>
        <article><h3>拆分测量延迟</h3><p>分别比较本地 / 公网、空载 / 大 POST 的上传耗时、首字节和首个 SSE 事件时间。仅凭 3 MB 请求无法承诺固定秒数收益。</p></article>
      </div>
      <div class="mt-5 flex flex-wrap gap-4 border-t pt-4 text-xs"><a href="https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/run-parameters/" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1">连接器参数 <ArrowUpRight class="h-3 w-3" /></a><a href="https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/origin-parameters/" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1">源站参数 <ArrowUpRight class="h-3 w-3" /></a><a href="https://developers.cloudflare.com/rules/configuration-rules/settings/" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1">Configuration Rules <ArrowUpRight class="h-3 w-3" /></a></div>
    </section>
  </div>
</template>
