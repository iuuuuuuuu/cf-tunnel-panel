<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { api, defaultOrigin, setCsrf, type Metrics, type MetricsSample, type Rule, type RuleInput, type State, type ScannedService } from "@/api";
import Badge from "@/components/ui/Badge.vue";
import Button from "@/components/ui/Button.vue";
import Card from "@/components/ui/Card.vue";
import Input from "@/components/ui/Input.vue";
import Label from "@/components/ui/Label.vue";
import {
  ArrowDown,
  ArrowUp,
  CloudUpload,
  Copy,
  ExternalLink,
  KeyRound,
  Loader2,
  LogOut,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Save,
  Search,
  Square,
  Trash2,
  X,
} from "lucide-vue-next";

import Modal from '@/components/ui/Modal.vue';
import ThemePicker from '@/components/ui/ThemePicker.vue';
import Select from '@/components/ui/Select.vue';
import Switch from '@/components/ui/Switch.vue';
import OriginFields from '@/components/OriginFields.vue';
import ConnectionSettings from '@/components/ConnectionSettings.vue';
import ApiToolkit from '@/components/ApiToolkit.vue';
import PerformanceOverview from '@/components/PerformanceOverview.vue';
import AccessDiagnostics from '@/components/AccessDiagnostics.vue';
import MonitoringCenter from '@/components/MonitoringCenter.vue';
import { Activity, Network, SlidersHorizontal, Terminal, Globe } from 'lucide-vue-next';
const section = ref('routes');
const apiHostname = ref('');
async function openApi(hostname: string) {
  apiHostname.value = hostname;
  section.value = 'api';
  await nextTick();
  window.scrollTo({top: 0, behavior: 'instant'});
}
const sections = [
  { id: 'routes', label: '总览与规则', short: '首页', icon: Network, subtitle: '服务连接与主机状态，一眼掌握。' },
  { id: 'connection', label: '连接设置', short: '连接', icon: SlidersHorizontal, subtitle: '按网络环境调整协议与连接方式。' },
  { id: 'api', label: 'API 与流式优化', short: 'API', icon: Globe, subtitle: '管理缓存策略，让流式响应保持顺畅。' },
  { id: 'metrics', label: '运行监控', short: '监控', icon: Activity, subtitle: '主机资源、实时流量与运行状态。' },
  { id: 'logs', label: '连接日志', short: '日志', icon: Terminal, subtitle: '查看连接事件与回源日志。' },
];
const currentSection = computed(() => sections.find(s => s.id === section.value)!);
const refreshError = ref('');
const metricsError = ref('');
const showDiagnostics = ref(false);
const pendingDelete = ref('');
const followLogs = ref(true);
const logQuery = ref('');
type FilterKind = "all" | "up" | "down" | "enabled" | "disabled";

const state = ref<State | null>(null);
const busy = ref(false);
const toast = ref<{ text: string; bad: boolean } | null>(null);

const query = ref("");
const flt = ref<FilterKind>("all");
const logLimit = ref(200);
const showForm = ref(false);
const editing = ref<string | null>(null);
const showToken = ref(false);
const showTunnelToken = ref(false);
const tunnelTokenInput = ref("");
const tunnelTokenBusy = ref(false);
const tokenInput = ref("");
const tokenBusy = ref(false);
const scanning = ref(false);
const scanned = ref<ScannedService[]>([]);
const logEl = ref<HTMLPreElement | null>(null);
const met = ref<Metrics | null>(null);
const cpuHist = ref<Partial<MetricsSample>[]>([]);

const form = ref({
  hostname: "",
  port: "",
  host: "127.0.0.1",
  scheme: "http",
  origin: defaultOrigin(),
  noTlsVerify: false,
  enabled: true,
  note: "",
});

let toastTimer = 0;
let pollTimer = 0;
let dragIndex = -1;

function notify(text: string, bad = false) {
  toast.value = { text, bad };
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toast.value = null), bad ? 8000 : 6000);
}

let refreshing = false;
let refreshingMetrics = false;
async function refreshState() {
  if (refreshing) return;
  refreshing = true;
  try {
    const st = await api.state();
    setCsrf(st.csrf);
    state.value = st;
    refreshError.value = '';
  } catch {
    refreshError.value = '连接状态刷新失败，正在显示上次数据。';
  } finally {
    refreshing = false;
  }
}
async function refreshMetrics() {
  if (refreshingMetrics) return;
  refreshingMetrics = true;
  try {
    const m = await api.metrics();
    met.value = m;
    cpuHist.value = [...cpuHist.value, {at:Date.now()/1000,cpu_pct:m.cpu_pct}].slice(-60);
    metricsError.value = '';
  } catch {
    metricsError.value = '监控更新失败，正在显示上次数据。';
  } finally {
    refreshingMetrics = false;
  }
}
async function refresh() {
  await Promise.all([refreshState(), refreshMetrics()]);
}
onMounted(() => {
  refresh();
  pollTimer = window.setInterval(refresh, 3000);
});
onUnmounted(() => { window.clearInterval(pollTimer); window.clearTimeout(toastTimer); });

async function guard(fn: () => Promise<void>, ok: string) {
  if (busy.value) {
    notify("上一个操作还在进行, 请稍候", true);
    return;
  }
  busy.value = true;
  try {
    await fn();
    notify(ok);
    await refresh();
  } catch (e: any) {
    notify(e && e.message ? e.message : "操作失败", true);
  } finally {
    busy.value = false;
  }
}

const rules = computed(() => state.value?.rules ?? []);
const running = computed(() => !!state.value?.running);
const tunnels = computed(() => state.value?.tunnels ?? []);
const totalLogs = computed(() => (state.value?.logs ?? []).length);
const visibleLogs = computed(() => {
  const all = (state.value?.logs ?? []).filter(line => line.toLowerCase().includes(logQuery.value.toLowerCase()));
  const n = logLimit.value;
  if (n <= 0 || n >= all.length) return all;
  return all.slice(all.length - n);
});
const logText = computed(() => visibleLogs.value.join("\n"));
const hasToken = computed(() => !!state.value?.has_cf_token);
const hasTunnelToken = computed(() => !!state.value?.has_tunnel_token);
const tunnelTokenPath = computed(() => state.value?.tunnel_token_path ?? "");
const tokenPath = computed(() => state.value?.cf_token_path ?? "");

watch(() => form.value.scheme, value => { if (value !== 'https') { form.value.origin.http2Origin = false; form.value.noTlsVerify = false; } });
watch(logText, async () => {
  await nextTick();
  const el = logEl.value;
  if (el && followLogs.value) el.scrollTop = el.scrollHeight;
});

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase();
  return rules.value.filter((r) => {
    if (flt.value === "up" && !r.port_open) return false;
    if (flt.value === "down" && r.port_open) return false;
    if (flt.value === "enabled" && !r.enabled) return false;
    if (flt.value === "disabled" && r.enabled) return false;
    if (!q) return true;
    return (
      r.hostname.toLowerCase().includes(q) ||
      r.service.toLowerCase().includes(q) ||
      (r.note || "").toLowerCase().includes(q)
    );
  });
});

function toPayload(r: Rule): RuleInput {
  return {
    hostname: r.hostname,
    port: r.port,
    service: r.service,
    host: r.host,
    scheme: r.scheme,
    noTlsVerify: r.noTlsVerify,
    enabled: r.enabled,
    note: r.note,
    origin: r.origin,
  };
}

function pushRules(next: RuleInput[]) {
  return api.setRules(next);
}

function resetForm() {
  form.value = {
    hostname: "",
    port: "",
    host: "127.0.0.1",
    scheme: "http",
    origin: defaultOrigin(),
    noTlsVerify: false,
    enabled: true,
    note: "",
  };
  editing.value = null;
  scanned.value = [];
}

function openAdd() {
  resetForm();
  showForm.value = true;
}

function openEdit(r: Rule) {
  editing.value = r.hostname;
  form.value = {
    hostname: r.hostname,
    port: String(r.port),
    host: r.host,
    scheme: r.scheme,
    noTlsVerify: r.noTlsVerify,
    enabled: r.enabled,
    note: r.note || "",
    origin: {...(r.origin || defaultOrigin())},
  };
  scanned.value = [];
  showForm.value = true;
}

async function submitForm() {
  const h = form.value.hostname.trim().toLowerCase();
  const p = Number(form.value.port);
  if (!h || !Number.isInteger(p) || p < 1 || p > 65535) {
    notify("请填写域名和 1–65535 的整数端口", true);
    return;
  }
  const clash = rules.value.some((r) => r.hostname === h && r.hostname !== editing.value);
  if (clash) {
    notify("这个域名已有规则", true);
    return;
  }
  const payload: RuleInput = {
    hostname: h,
    port: p,
    host: form.value.host.trim() || "127.0.0.1",
    scheme: form.value.scheme,
    noTlsVerify: form.value.noTlsVerify,
    enabled: form.value.enabled,
    note: form.value.note.trim(),
    origin: {...form.value.origin},
  };
  const isEdit = !!editing.value;
  await guard(async () => {
    const next = isEdit
      ? rules.value.map((r) => (r.hostname === editing.value ? payload : toPayload(r)))
      : [...rules.value.map(toPayload), payload];
    await pushRules(next);
    await api.save();
    showForm.value = false;
    resetForm();
  }, isEdit ? "已保存 " + h : "已添加 " + h);
}

async function scanLocal() {
  scanning.value = true;
  try {
    const r = await api.scan();
    scanned.value = r.services || [];
    if (scanned.value.length === 0) notify("没扫描到监听中的服务", true);
  } catch (e: any) {
    notify(e && e.message ? e.message : "扫描失败", true);
  } finally {
    scanning.value = false;
  }
}

async function toggleRule(hostname: string) {
  const next = rules.value.map(toPayload).map((r) =>
    r.hostname === hostname ? { ...r, enabled: !r.enabled } : r
  );
  const target = next.find((r) => r.hostname === hostname);
  await guard(async () => {
    await pushRules(next);
    await api.save();
  }, target && target.enabled ? "已启用 " + hostname : "已禁用 " + hostname);
}

async function move(index: number, delta: number) {
  const next = rules.value.map(toPayload);
  const j = index + delta;
  if (j < 0 || j >= next.length) return;
  const tmp = next[index];
  next[index] = next[j];
  next[j] = tmp;
  await guard(async () => {
    await pushRules(next);
    await api.save();
  }, "顺序已更新");
}

async function remove(hostname: string) {
  const next = rules.value.filter((r) => r.hostname !== hostname).map(toPayload);
  await guard(async () => {
    await pushRules(next);
    await api.save();
    pendingDelete.value = "";
  }, "已删除 " + hostname);
}

function onDragStart(index: number) {
  dragIndex = index;
}

function onDrop(target: number) {
  const from = dragIndex;
  dragIndex = -1;
  if (from < 0 || from === target) return;
  const next = rules.value.map(toPayload);
  const [item] = next.splice(from, 1);
  next.splice(target, 0, item);
  guard(async () => {
    await pushRules(next);
    await api.save();
  }, "顺序已更新");
}

async function copy(text: string) {
  try {
    if (window.isSecureContext && navigator.clipboard) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "readonly");
      ta.style.position = "fixed";
      ta.style.top = "0";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (!ok) throw new Error("execCommand 被拒绝");
    }
    notify("已复制: " + text);
  } catch (e) {
    notify("复制失败, 请手动选中复制", true);
  }
}

function openPublic(hostname: string) {
  window.open("https://" + hostname + "/", "_blank", "noopener");
}

async function saveTunnelToken() {
  const t = tunnelTokenInput.value.trim();
  if (!t) {
    notify("先填入隧道 token", true);
    return;
  }
  tunnelTokenBusy.value = true;
  try {
    await api.setTunnelToken(t);
    tunnelTokenInput.value = "";
    showTunnelToken.value = false;
    await refresh();
    notify("已保存隧道 token（下次启动生效）");
  } catch (e: any) {
    notify(e && e.message ? e.message : "保存失败", true);
  } finally {
    tunnelTokenBusy.value = false;
  }
}

async function clearTunnelToken() {
  tunnelTokenBusy.value = true;
  try {
    await api.setTunnelToken("");
    showTunnelToken.value = false;
    await refresh();
    notify("已清除隧道 token");
  } catch (e: any) {
    notify(e && e.message ? e.message : "清除失败", true);
  } finally {
    tunnelTokenBusy.value = false;
  }
}

async function saveToken() {
  const t = tokenInput.value.trim();
  if (!t) {
    notify("先填入 Cloudflare API Token", true);
    return;
  }
  tokenBusy.value = true;
  try {
    await api.setCfToken(t);
    tokenInput.value = "";
    showToken.value = false;
    await refresh();
    notify("已保存 Cloudflare 密钥");
  } catch (e: any) {
    notify(e && e.message ? e.message : "保存失败", true);
  } finally {
    tokenBusy.value = false;
  }
}

async function clearToken() {
  tokenBusy.value = true;
  try {
    await api.setCfToken("");
    showToken.value = false;
    await refresh();
    notify("已清除 Cloudflare 密钥");
  } catch (e: any) {
    notify(e && e.message ? e.message : "清除失败", true);
  } finally {
    tokenBusy.value = false;
  }
}

const filterOptions: { key: FilterKind; label: string }[] = [
  { key: "all", label: "全部" },
  { key: "up", label: "通" },
  { key: "down", label: "不通" },
  { key: "enabled", label: "已启用" },
  { key: "disabled", label: "已禁用" },
];
</script>

<template>
  <div class="panel-shell min-h-full text-foreground">
    <header class="panel-header sticky top-0 z-10 border-b bg-card/85 backdrop-blur-xl">
      <div class="mx-auto flex h-14 max-w-[1400px] items-center gap-2 px-3 md:gap-3 md:px-6">
        <div class="brand-mark"><Network class="h-5 w-5" /></div><h1 class="whitespace-nowrap text-sm font-semibold tracking-tight">Tunnel Panel<span class="hidden pl-2 text-xs font-normal text-muted-foreground sm:inline">连接控制台</span></h1>
        <Badge class="hidden sm:inline-flex" :variant="running ? 'success' : state?.external ? 'warning' : 'muted'">
          {{ running ? "● 运行中" : state?.external ? "● 外部进程" : "● 已停止" }}
        </Badge>
        <span v-if="state?.conn" class="hidden text-xs text-muted-foreground sm:inline">{{ state.conn }}</span>
        <div class="flex-1" />
        <ThemePicker />
        <Button variant="ghost" size="sm" @click="api.logout()">
          <LogOut class="h-4 w-4" />
          退出
        </Button>
      </div>
    </header>

    <div class="workspace-layout">
    <nav class="workspace-nav" aria-label="主导航">
      <div class="eyebrow hidden px-3 pb-4 lg:block">WORKSPACE</div>
      <button v-for="item in sections" :key="item.id" type="button" :class="{active: section === item.id}" :aria-label="item.label" :aria-current="section === item.id ? 'page' : undefined" @click="section = item.id"><component :is="item.icon" class="h-4 w-4 shrink-0" /><span class="hidden md:inline">{{ item.label }}</span><span class="md:hidden">{{ item.short }}</span><span v-if="item.id === 'routes'" class="nav-count">{{ rules.length }}</span></button>
      <div class="nav-footer"><span class="status-dot" :class="running ? 'online' : ''" />{{ running ? '连接器运行中' : '连接器未运行' }}<p class="mt-2 text-xs text-muted-foreground">{{ hasTunnelToken ? '远程管理模式' : '本地管理模式' }}</p></div>
    </nav>
    <main class="workspace-main">
      <div class="page-heading"><div><div class="eyebrow">YOUR CONNECTION SPACE</div><h1>{{ currentSection.label }}</h1><p>{{ currentSection.subtitle }}</p></div><div class="flex shrink-0 gap-2"><Button variant="outline" class="px-3" aria-label="访问诊断" @click="showDiagnostics = true"><Activity class="h-4 w-4" /><span class="hidden sm:inline">访问</span>诊断</Button><Button variant="outline" class="px-3" @click="refresh"><RefreshCw class="h-4 w-4" /><span class="hidden sm:inline">刷新</span></Button></div></div>
      <div v-if="refreshError" class="info-strip" role="alert">{{ refreshError }}</div>
      <div v-if="state?.tunnels_error" class="info-strip" role="status">{{ state.tunnels_error }}（保留上次列表）</div>
      <div v-if="!state && !refreshError" class="info-strip" role="status">正在加载隧道配置…</div>
      <PerformanceOverview v-if="section === 'routes'" :metrics="met" :history="cpuHist" :error="metricsError" />
      <MonitoringCenter v-if="section === 'metrics'" @notice="notify" />
      <div v-if="section === 'routes'" class="summary-grid">
        <div><span>连接状态</span><strong>{{ running ? '运行中' : state?.external ? '外部进程' : '已停止' }}</strong><small>{{ state?.conn || '等待连接器事件' }}</small></div>
        <div><span>转发服务</span><strong>{{ rules.filter(r => r.enabled).length }}<em> / {{ rules.length }}</em></strong><small>已启用 / 全部规则</small></div>
        <div><span>源站连通</span><strong>{{ rules.filter(r => r.port_open).length }}<em> 个</em></strong><small>本机 TCP 端口检测</small></div>
      </div>
      <ConnectionSettings v-if="section === 'connection' && state" :key="state.config_path" :settings="state.connection" :running="running" :remote="hasTunnelToken" @saved="refresh" @notice="notify" />
      <ApiToolkit v-if="section === 'api'" v-model:hostname="apiHostname" :rules="rules" :has-token="hasToken" @notice="notify" @token="showToken = true" />
      <Card v-if="section === 'routes'">
        <div class="p-6 pb-3 text-base font-semibold leading-none tracking-tight">连接器控制</div>
        <div class="space-y-3 p-6 pt-0">
          <div class="flex flex-wrap gap-2">
            <Button :disabled="busy" @click="guard(() => api.save().then(() => undefined), '已保存并校验')">
              <Loader2 v-if="busy" class="h-4 w-4 animate-spin" />
              <Save v-else class="h-4 w-4" />
              保存并校验
            </Button>
            <Button variant="outline" :disabled="busy || running" @click="guard(() => api.start().then(() => undefined), '已启动隧道')">
              <Play class="h-4 w-4" />
              启动隧道
            </Button>
            <Button variant="outline" :disabled="busy || !running" @click="guard(() => api.stop().then(() => undefined), '已停止隧道')">
              <Square class="h-4 w-4" />
              停止隧道
            </Button>
            <Button
              variant="outline"
              :disabled="busy || !hasToken"
              :title="hasToken ? '按规则同步 DNS 记录' : '未配置 Cloudflare 密钥, 无法同步 DNS'"
              @click="
                guard(async () => {
                  const r = await api.syncDns();
                  notify((r.messages || []).join(' | ') || 'DNS 已同步');
                }, 'DNS 已同步')
              "
            >
              <CloudUpload class="h-4 w-4" />
              同步 DNS
            </Button>
            <Button variant="ghost" @click="showToken = true">
              <KeyRound class="h-4 w-4" />
              Cloudflare 密钥
              <Badge :variant="hasToken ? 'success' : 'muted'" class="ml-1">{{ hasToken ? "已配置" : "未配置" }}</Badge>
            </Button>
          </div>
          <p class="text-xs text-muted-foreground">
            保存会写入 cloudflared 配置并校验; 若隧道正在运行, 会自动按新配置重启。
          </p>
        </div>
      </Card>

      <Card v-if="section === 'routes'">
        <div class="p-6 pb-3 text-base font-semibold leading-none tracking-tight">隧道</div>
        <div class="space-y-2 p-6 pt-0">
          <div class="flex flex-wrap items-end gap-2">
            <div class="min-w-[200px] flex-1 space-y-1.5">
              <Label for="tunnel">选择隧道</Label>
              <div class="relative">
                <Select id="tunnel" label="选择隧道（运行时请先停止）" :disabled="busy || running" :model-value="state?.tunnel ?? ''" :options="tunnels.length ? tunnels.map(t => ({value:t.id,label:t.name})) : [{value:state?.tunnel ?? '',label:state?.tunnel || '无可用隧道'}]" @update:model-value="value => guard(() => api.setTunnel(value).then(() => undefined), '已切换隧道')" />
              </div>
            </div>
            <Button variant="outline" @click="showTunnelToken = true">
              <KeyRound class="h-4 w-4" />
              隧道 Token
              <Badge :variant="hasTunnelToken ? 'success' : 'muted'" class="ml-1">{{ hasTunnelToken ? "已配置" : "未配置" }}</Badge>
            </Button>
            <Button @click="openAdd">
              <Plus class="h-4 w-4" />
              添加转发规则
            </Button>
          </div>
          <p class="break-all font-mono text-xs text-muted-foreground">{{ state?.config_path }}</p><div v-if="hasTunnelToken" class="info-strip">远程管理：本页转发规则仅保存在本地，实际转发以 Cloudflare 后台为准。</div>
        </div>
      </Card>


      <Card v-if="section === 'routes'">
        <div class="flex flex-wrap items-center gap-2 p-6 pb-3">
          <div class="text-base font-semibold leading-none tracking-tight">转发规则</div>
          <span class="text-xs text-muted-foreground">{{ filtered.length }} / {{ rules.length }} 条</span>
          <div class="flex-1" />
          <div class="relative">
            <Search class="pointer-events-none absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input v-model="query" class="w-full sm:w-64 pl-8" placeholder="搜索域名 / 目标 / 备注" />
          </div>
        </div>
        <div class="space-y-3 px-6 pb-6 pt-0">
          <div class="flex flex-wrap gap-1.5">
            <Button
              v-for="opt in filterOptions"
              :key="opt.key"
              size="sm"
              :variant="flt === opt.key ? 'default' : 'outline'"
              @click="flt = opt.key"
            >
              {{ opt.label }}
            </Button>
          </div>
          <div class="hidden overflow-x-auto md:block">
            <table class="w-full caption-bottom text-sm">
            <thead>
              <tr class="border-b">
                <th class="h-9 w-8 px-1" />
                <th class="h-9 px-2 text-left align-middle text-xs font-medium text-muted-foreground">公网域名</th>
                <th class="h-9 w-40 px-2 text-left align-middle text-xs font-medium text-muted-foreground">备注</th>
                <th class="h-9 px-2 text-left align-middle text-xs font-medium text-muted-foreground">转发目标</th>
                <th class="h-9 w-16 px-2 text-left align-middle text-xs font-medium text-muted-foreground">检测</th>
                <th class="h-9 w-20 px-2 text-left align-middle text-xs font-medium text-muted-foreground">状态</th>
                <th class="h-9 w-64 px-2 text-left align-middle text-xs font-medium text-muted-foreground">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="filtered.length === 0" class="border-b">
                <td colspan="7" class="px-2 py-6 text-center text-sm text-muted-foreground">
                  {{ rules.length === 0 ? "还没有规则" : "没有符合筛选条件的规则" }}
                </td>
              </tr>
              <tr
                v-for="r in filtered"
                :key="r.hostname"
                class="border-b transition-colors hover:bg-muted/50"
                :class="r.enabled ? '' : 'opacity-55'"
                @dragover.prevent
                @drop="onDrop(rules.findIndex((x) => x.hostname === r.hostname))"
              >
                <td class="px-1 py-2.5 align-middle">
                  <span
                    class="cursor-grab select-none text-muted-foreground"
                    title="拖动排序"
                    draggable="true"
                    @dragstart="onDragStart(rules.findIndex((x) => x.hostname === r.hostname))"
                  >⋮⋮</span>
                </td>
                <td class="px-2 py-2.5 align-middle">
                  <div class="flex items-center gap-1.5 font-medium">
                    <span>{{ r.hostname }}</span>
                    <button class="text-muted-foreground hover:text-foreground" title="复制域名" @click="copy(r.hostname)">
                      <Copy class="h-3.5 w-3.5" />
                    </button>
                    <button class="text-muted-foreground hover:text-foreground" title="打开公网地址" @click="openPublic(r.hostname)">
                      <ExternalLink class="h-3.5 w-3.5" />
                    </button>
                  </div>
                </td>
                <td class="px-2 py-2.5 align-middle text-xs text-muted-foreground">
                  <span :title="r.note">{{ r.note || "-" }}</span>
                </td>
                <td class="px-2 py-2.5 align-middle font-mono text-xs text-muted-foreground">
                  <div class="flex items-center gap-1.5">
                    <span>{{ r.service }}</span>
                    <button class="text-muted-foreground hover:text-foreground" title="复制转发目标" @click="copy(r.service)">
                      <Copy class="h-3.5 w-3.5" />
                    </button>
                  </div>
                </td>
                <td class="px-2 py-2.5 align-middle">
                  <Badge :variant="r.port_open ? 'success' : 'destructive'">{{ r.port_open ? "通" : "不通" }}</Badge>
                </td>
                <td class="px-2 py-2.5 align-middle">
                  <button
                    class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs transition-colors"
                    :class="r.enabled ? 'border-emerald-300 text-emerald-700' : 'border-input text-muted-foreground'"
                    @click="toggleRule(r.hostname)"
                  >
                    {{ r.enabled ? "已启用" : "已禁用" }}
                  </button>
                </td>
                <td class="px-2 py-2.5 align-middle">
                  <div class="flex flex-wrap gap-1">
                    <Button variant="outline" size="sm" :aria-label="r.hostname + ' 的 API 与流式配置'" title="配置此域名的 API / 流式规则" @click="openApi(r.hostname)"><SlidersHorizontal class="h-3.5 w-3.5" /><span>API / 流式</span></Button>
                    <Button variant="outline" size="icon" title="编辑" @click="openEdit(r)">
                      <Pencil class="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="outline" size="icon" title="上移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), -1)">
                      <ArrowUp class="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="outline" size="icon" title="下移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), 1)">
                      <ArrowDown class="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="outline" size="icon" title="删除" @click="pendingDelete = r.hostname">
                      <Trash2 class="h-3.5 w-3.5 text-red-600" />
                    </Button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          </div>

          <div class="space-y-2 md:hidden">
            <div
              v-if="filtered.length === 0"
              class="rounded-md border px-3 py-6 text-center text-sm text-muted-foreground"
            >
              {{ rules.length === 0 ? "还没有规则" : "没有符合筛选条件的规则" }}
            </div>
            <div
              v-for="r in filtered"
              :key="'m-' + r.hostname"
              class="rounded-lg border p-3"
              :class="r.enabled ? '' : 'opacity-55'"
            >
              <div class="flex items-start justify-between gap-2">
                <div class="min-w-0">
                  <div class="flex items-center gap-1.5 font-medium">
                    <span class="truncate">{{ r.hostname }}</span>
                    <button class="text-muted-foreground" title="复制域名" @click="copy(r.hostname)">
                      <Copy class="h-3.5 w-3.5" />
                    </button>
                    <button class="text-muted-foreground" title="打开公网地址" @click="openPublic(r.hostname)">
                      <ExternalLink class="h-3.5 w-3.5" />
                    </button>
                  </div>
                  <div class="mt-0.5 flex items-center gap-1.5 truncate font-mono text-xs text-muted-foreground">
                    <span class="truncate">{{ r.service }}</span>
                    <button class="text-muted-foreground" title="复制转发目标" @click="copy(r.service)">
                      <Copy class="h-3 w-3" />
                    </button>
                  </div>
                  <div v-if="r.note" class="mt-0.5 text-xs text-muted-foreground">备注: {{ r.note }}</div>
                </div>
                <Badge :variant="r.port_open ? 'success' : 'destructive'">{{ r.port_open ? "通" : "不通" }}</Badge>
              </div>
              <div class="mt-2 flex flex-wrap items-center gap-1.5">
                <button
                  class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs"
                  :class="r.enabled ? 'border-emerald-300 text-emerald-700' : 'border-input text-muted-foreground'"
                  @click="toggleRule(r.hostname)"
                >
                  {{ r.enabled ? "已启用" : "已禁用" }}
                </button>
                <div class="flex-1" />
                <Button variant="outline" size="sm" :aria-label="r.hostname + ' 的 API 与流式配置'" title="配置此域名的 API / 流式规则" @click="openApi(r.hostname)"><SlidersHorizontal class="h-3.5 w-3.5" /><span>API / 流式</span></Button>
                    <Button variant="outline" size="icon" title="编辑" @click="openEdit(r)">
                  <Pencil class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" title="上移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), -1)">
                  <ArrowUp class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" title="下移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), 1)">
                  <ArrowDown class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" title="删除" @click="pendingDelete = r.hostname">
                  <Trash2 class="h-3.5 w-3.5 text-red-600" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </Card>

      <Card v-if="section === 'logs'">
        <div class="flex flex-wrap items-center gap-2 p-6 pb-3">
          <div class="text-base font-semibold leading-none tracking-tight">日志</div>
          <span class="text-xs text-muted-foreground">共 {{ totalLogs }} 条, 显示最近 {{ visibleLogs.length }} 条</span>
          <div class="flex-1" />
          <div class="relative">
            <Select v-model="logLimit" label="日志条数" :options="[{value:50,label:'50 条'},{value:100,label:'100 条'},{value:200,label:'200 条'},{value:0,label:'全部'}]" />
          </div>
        </div>
        <div class="p-6 pt-0">
          <div class="mb-3 flex flex-wrap items-center gap-3"><Input v-model="logQuery" class="max-w-sm" placeholder="搜索日志关键字…" /><Switch v-model="followLogs" label="自动滚动" /></div>
          <pre ref="logEl" class="h-40 overflow-auto rounded-lg bg-muted/50 p-4 text-xs leading-relaxed text-foreground md:h-[480px]">{{ logText || "暂无匹配日志，启动隧道后可在此查看连接事件。" }}</pre>
        </div>
      </Card>
    </main>
    </div>

    <Modal v-model="showForm" label="转发规则" :busy="busy">
          <div class="mb-4 flex items-center justify-between">
            <div class="text-base font-semibold">{{ editing ? "编辑转发规则" : "添加转发规则" }}</div>
            <button class="text-muted-foreground hover:text-foreground" @click="showForm = false">
              <X class="h-4 w-4" />
            </button>
          </div>
          <form class="space-y-3" @submit.prevent="submitForm">
            <div class="space-y-1.5">
              <Label for="f-host">公网域名</Label>
              <Input id="f-host" v-model="form.hostname" placeholder="a.example.com" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div class="space-y-1.5">
                <Label for="f-origin">源站主机</Label>
                <Input id="f-origin" v-model="form.host" placeholder="127.0.0.1" />
              </div>
              <div class="space-y-1.5">
                <Label for="f-port">端口</Label>
                <Input id="f-port" v-model="form.port" type="number" placeholder="8080" />
              </div>
            </div>
            <div class="space-y-1.5">
              <Label for="f-note">备注</Label>
              <Input id="f-note" v-model="form.note" placeholder="例如: 宝塔面板" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div class="space-y-1.5">
                <Label for="f-scheme">协议</Label>
                <div class="relative">
                  <Select id="f-scheme" label="源站协议" v-model="form.scheme" :options="[{value:'http',label:'HTTP'},{value:'https',label:'HTTPS'}]" />
                </div>
              </div>
              <div class="flex items-end"><Switch v-model="form.enabled" label="启用规则" /></div>
            </div>
            <Switch v-model="form.noTlsVerify" label="跳过源站证书校验" description="仅适用于受控的自签名 HTTPS 源站；默认校验证书。" :disabled="form.scheme !== 'https'" />
            <details class="advanced-section"><summary>源站连接与流式设置<span>超时 · HTTP/2 · 连接复用</span></summary><div class="pt-4"><OriginFields v-model="form.origin" :scheme="form.scheme" /></div></details>
            <div v-if="hasTunnelToken" class="info-strip">远程管理模式：本地规则不会应用到云端，请在 Cloudflare 后台配置转发。</div>

            <div class="rounded-md border p-3">
              <div class="mb-2 flex flex-wrap items-center gap-2">
                <span class="text-xs font-medium">扫描本机服务</span>
                <Button type="button" variant="outline" size="sm" :disabled="scanning" @click="scanLocal">
                  <RefreshCw class="h-3.5 w-3.5" :class="scanning ? 'animate-spin' : ''" />
                  扫描
                </Button>
                <span v-if="scanned.length" class="text-xs text-muted-foreground">点一行即可填入端口</span>
              </div>
              <div v-if="scanned.length" class="max-h-36 overflow-auto">
                <button
                  v-for="s in scanned"
                  :key="s.port + s.process + s.addr"
                  type="button"
                  class="flex w-full items-center justify-between rounded px-2 py-1 text-left text-xs transition-colors hover:bg-accent"
                  @click="form.port = String(s.port)"
                >
                  <span class="font-mono">{{ s.addr }}:{{ s.port }}</span>
                  <span class="text-muted-foreground">{{ s.process || "-" }}</span>
                </button>
              </div>
              <p v-else class="text-xs text-muted-foreground">点「扫描」列出本机正在监听的端口与进程</p>
            </div>

            <div class="flex justify-end gap-2 pt-1">
              <Button variant="outline" type="button" @click="showForm = false">取消</Button>
              <Button type="submit" :disabled="busy">{{ editing ? "保存修改" : "添加" }}</Button>
            </div>
          </form>
    </Modal>

    <Modal v-model="showDiagnostics" label="访问诊断">
      <AccessDiagnostics v-if="showDiagnostics" :rules="rules" :running="running" :external="!!state?.external" :connection="state?.connection ?? {protocol:'http2', 'edge-ip-version':'4', region:'', loglevel:'info'}" @changed="refresh" @close="showDiagnostics = false" @settings="showDiagnostics = false; section = 'connection'" @api="showDiagnostics = false; section = 'api'" />
    </Modal>

    <Modal v-model="showTunnelToken" label="隧道 Token" :busy="tunnelTokenBusy">
          <div class="mb-4 flex items-center justify-between">
            <div class="text-base font-semibold">隧道 Token</div>
            <button class="text-muted-foreground hover:text-foreground" @click="showTunnelToken = false">
              <X class="h-4 w-4" />
            </button>
          </div>
          <div class="space-y-3">
            <div class="flex items-center gap-2 text-sm">
              <Badge :variant="hasTunnelToken ? 'success' : 'muted'">{{ hasTunnelToken ? "已配置" : "未配置" }}</Badge>
              <span class="text-xs text-muted-foreground">配置后用 cloudflared run --token 启动, 不需要 cert.pem</span>
            </div>
            <div class="rounded-md border border-amber-300 bg-amber-100 px-3 py-2 text-xs text-amber-700">
              注意: Cloudflare 后台创建的隧道属于「远程管理」, 转发规则以 Cloudflare 后台为准, 本页规则表此时不生效。
            </div>
            <div class="space-y-1.5">
              <Label for="tt-path">保存位置</Label>
              <div class="flex items-center gap-1.5">
                <code class="flex-1 truncate rounded border bg-muted/50 px-2 py-1.5 font-mono text-xs">{{ tunnelTokenPath }}</code>
                <Button variant="outline" size="sm" title="复制路径" @click="copy(tunnelTokenPath)">
                  <Copy class="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
            <div class="space-y-1.5">
              <Label for="tt">Token</Label>
              <Input id="tt" v-model="tunnelTokenInput" type="password" placeholder="eyJhIjoi... （cloudflared tunnel token 输出的整串）" />
            </div>
            <div class="flex justify-end gap-2 pt-1">
              <Button variant="outline" type="button" :disabled="tunnelTokenBusy || !hasTunnelToken" @click="clearTunnelToken">清除</Button>
              <Button type="button" :disabled="tunnelTokenBusy" @click="saveTunnelToken">保存</Button>
            </div>
          </div>
    </Modal>

    <Modal v-model="showToken" label="Cloudflare API Token" :busy="tokenBusy">
          <div class="mb-4 flex items-center justify-between">
            <div class="text-base font-semibold">Cloudflare API Token</div>
            <button class="text-muted-foreground hover:text-foreground" @click="showToken = false">
              <X class="h-4 w-4" />
            </button>
          </div>
          <div class="space-y-3">
            <div class="flex items-center gap-2 text-sm">
              <Badge :variant="hasToken ? 'success' : 'muted'">{{ hasToken ? "已配置" : "未配置" }}</Badge>
              <span class="text-xs text-muted-foreground">用于 DNS、云端设置和缓存规则；按需要授予对应权限</span>
            </div>
            <div class="space-y-1.5">
              <Label for="cf-path">保存位置</Label>
              <div class="flex items-center gap-1.5">
                <code class="flex-1 truncate rounded border bg-muted/50 px-2 py-1.5 font-mono text-xs" id="cf-path">{{ tokenPath }}</code>
                <Button variant="outline" size="sm" title="复制路径" @click="copy(tokenPath)">
                  <Copy class="h-3.5 w-3.5" />
                </Button>
              </div>
              <p class="text-xs text-muted-foreground">SSH 登录后可直接查看该文件确认</p>
            </div>
            <div class="space-y-1.5">
              <Label for="cf">Token</Label>
              <Input id="cf" v-model="tokenInput" type="password" placeholder="Zone Read；DNS / Zone Settings / Cache Rules 按需授权" />
            </div>
            <div class="flex justify-end gap-2 pt-1">
              <Button variant="outline" type="button" :disabled="tokenBusy || !hasToken" @click="clearToken">清除</Button>
              <Button type="button" :disabled="tokenBusy" @click="saveToken">保存</Button>
            </div>
          </div>
    </Modal>

    <div v-if="pendingDelete" class="fixed inset-0 z-20 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-label="删除规则">
      <div class="w-full max-w-md rounded-xl border bg-card p-6 shadow-xl"><h2 class="text-lg font-semibold">删除转发规则？</h2><p class="my-4 break-all text-sm text-muted-foreground">{{ pendingDelete }} 的本地转发配置将被删除。DNS 记录会保留。</p><div class="flex justify-end gap-2"><Button variant="outline" @click="pendingDelete = ''">取消</Button><Button variant="destructive" :disabled="busy" @click="remove(pendingDelete)">删除规则</Button></div></div>
    </div>
    <Teleport to="body"><div
      v-if="toast"
      :role="toast.bad ? 'alert' : 'status'"
      aria-live="polite"
      class="panel-toast fixed right-4 z-[100] flex items-start gap-3 max-w-sm rounded-xl px-4 py-2.5 text-sm text-white shadow-lg"
      :class="toast.bad ? 'bg-red-600' : 'bg-zinc-900'"
    >
      <span class="min-w-0 flex-1 break-words">{{ toast.text }}</span>
      <button type="button" aria-label="关闭通知" class="shrink-0 pt-0.5 text-white/80 hover:text-white" @click="toast = null"><X class="h-4 w-4" /></button>
    </div></Teleport>
  </div>
</template>
