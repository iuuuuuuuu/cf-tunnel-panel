<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { api, setCsrf, type Metrics, type Rule, type RuleInput, type State, type ScannedService } from "@/api";
import Badge from "@/components/ui/Badge.vue";
import Button from "@/components/ui/Button.vue";
import Card from "@/components/ui/Card.vue";
import Input from "@/components/ui/Input.vue";
import Label from "@/components/ui/Label.vue";
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  CloudUpload,
  Copy,
  ExternalLink,
  KeyRound,
  Loader2,
  LogOut,
  Moon,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Save,
  Search,
  Square,
  Sun,
  Trash2,
  X,
} from "lucide-vue-next";

type FilterKind = "all" | "up" | "down" | "enabled" | "disabled";

const state = ref<State | null>(null);
const busy = ref(false);
const toast = ref<{ text: string; bad: boolean } | null>(null);
const theme = ref<"light" | "dark">("light");
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
const cpuHist = ref<number[]>([]);

const form = ref({
  hostname: "",
  port: "",
  host: "127.0.0.1",
  scheme: "http",
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
  toastTimer = window.setTimeout(() => (toast.value = null), 3200);
}

function applyTheme(next: "light" | "dark") {
  theme.value = next;
  document.documentElement.classList.toggle("dark", next === "dark");
  window.localStorage.setItem("cftheme", next);
}

function initTheme() {
  const saved = window.localStorage.getItem("cftheme");
  if (saved === "light" || saved === "dark") {
    applyTheme(saved);
    return;
  }
  applyTheme(window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}

function toggleTheme() {
  applyTheme(theme.value === "dark" ? "light" : "dark");
}

async function refresh() {
  try {
    const st = await api.state();
    setCsrf(st.csrf);
    state.value = st;
    const m = await api.metrics();
    met.value = m;
    const next = cpuHist.value.concat([Math.round(m.cpu_pct)]);
    cpuHist.value = next.length > 60 ? next.slice(next.length - 60) : next;
  } catch (e) {
    /* 401 已由 api 跳转 */
  }
}

onMounted(() => {
  initTheme();
  refresh();
  pollTimer = window.setInterval(refresh, 3000);
});
onUnmounted(() => window.clearInterval(pollTimer));

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
  const all = state.value?.logs ?? [];
  const n = logLimit.value;
  if (n <= 0 || n >= all.length) return all;
  return all.slice(all.length - n);
});
const logText = computed(() => visibleLogs.value.join("\n"));
const hasToken = computed(() => !!state.value?.has_cf_token);
const hasTunnelToken = computed(() => !!state.value?.has_tunnel_token);
const tunnelTokenPath = computed(() => state.value?.tunnel_token_path ?? "");
const tokenPath = computed(() => state.value?.cf_token_path ?? "");

watch(logText, async () => {
  await nextTick();
  const el = logEl.value;
  if (el) el.scrollTop = el.scrollHeight;
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
  };
  scanned.value = [];
  showForm.value = true;
}

async function submitForm() {
  const h = form.value.hostname.trim().toLowerCase();
  const p = Number(form.value.port);
  if (!h || !p) {
    notify("域名和端口都要填", true);
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

function fmtSize(kb: number): string {
  if (!kb) return "-";
  const gb = kb / 1024 / 1024;
  return gb >= 1 ? gb.toFixed(1) + " GB" : Math.round(kb / 1024) + " MB";
}

function fmtRate(bps: number): string {
  if (!bps || bps < 1) return "0 B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let v = bps;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return v.toFixed(v >= 10 ? 0 : 1) + " " + units[i];
}

function fmtUptime(secs: number): string {
  if (!secs) return "-";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return d + " 天 " + h + " 小时";
  if (h > 0) return h + " 小时 " + m + " 分";
  return m + " 分";
}

function pctOf(used: number, total: number): number {
  if (!total) return 0;
  return Math.min(100, Math.max(0, Math.round((used / total) * 100)));
}

const memPct = computed(() => {
  const m = met.value;
  if (!m || !m.mem_total_kb) return 0;
  return pctOf(m.mem_total_kb - m.mem_avail_kb, m.mem_total_kb);
});
const diskPct = computed(() => {
  const m = met.value;
  if (!m || !m.disk_total_kb) return 0;
  return pctOf(m.disk_used_kb, m.disk_total_kb);
});
// Linux 才有 /proc; Windows 桌面端采不到, 不能显示成 0 装作正常
const metricsSupported = computed(() => {
  const m = met.value;
  return !!m && m.mem_total_kb > 0;
});

const cpuSpark = computed(() => {
  const h = cpuHist.value;
  if (h.length < 2) return "";
  const w = 240;
  const ht = 40;
  return h
    .map((v, i) => {
      const x = (i / (h.length - 1)) * w;
      const y = ht - (Math.min(100, Math.max(0, v)) / 100) * ht;
      return x.toFixed(1) + "," + y.toFixed(1);
    })
    .join(" ");
});

const filterOptions: { key: FilterKind; label: string }[] = [
  { key: "all", label: "全部" },
  { key: "up", label: "通" },
  { key: "down", label: "不通" },
  { key: "enabled", label: "已启用" },
  { key: "disabled", label: "已禁用" },
];
</script>

<template>
  <div class="min-h-full bg-background pb-10 text-foreground">
    <header class="sticky top-0 z-10 border-b bg-card/85 backdrop-blur">
      <div class="mx-auto flex h-14 max-w-5xl items-center gap-2 px-3 md:gap-3 md:px-6">
        <h1 class="text-base font-semibold">内网穿透面板</h1>
        <Badge :variant="running ? 'success' : state?.external ? 'warning' : 'muted'">
          {{ running ? "● 运行中" : state?.external ? "● 外部进程" : "● 已停止" }}
        </Badge>
        <span v-if="state?.conn" class="hidden text-xs text-muted-foreground sm:inline">{{ state.conn }}</span>
        <div class="flex-1" />
        <Button variant="ghost" size="sm" :title="theme === 'dark' ? '切到浅色' : '切到深色'" @click="toggleTheme">
          <Sun v-if="theme === 'dark'" class="h-4 w-4" />
          <Moon v-else class="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="sm" @click="api.logout()">
          <LogOut class="h-4 w-4" />
          退出
        </Button>
      </div>
    </header>

    <main class="mx-auto max-w-5xl space-y-4 px-3 pt-4 md:px-6 md:pt-5">
      <Card>
        <div class="p-6 pb-3 text-base font-semibold leading-none tracking-tight">操作</div>
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

      <Card>
        <div class="p-6 pb-3 text-base font-semibold leading-none tracking-tight">隧道</div>
        <div class="space-y-2 p-6 pt-0">
          <div class="flex items-end gap-2">
            <div class="max-w-sm flex-1 space-y-1.5">
              <Label for="tunnel">选择隧道</Label>
              <div class="relative">
                <select
                  id="tunnel"
                  :value="state?.tunnel ?? ''"
                  class="h-9 w-full appearance-none rounded-md border border-input bg-background pl-3 pr-9 text-sm shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  @change="(e) => guard(() => api.setTunnel((e.target as HTMLSelectElement).value).then(() => undefined), '已切换隧道')"
                >
                  <option v-if="tunnels.length === 0" :value="state?.tunnel ?? ''">
                    {{ state?.tunnel || "（无可用隧道）" }}
                  </option>
                  <option v-for="t in tunnels" :key="t.id" :value="t.id">{{ t.name }}</option>
                </select>
                <ChevronDown class="pointer-events-none absolute right-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
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
          <p class="text-xs text-muted-foreground">{{ state?.config_path }}</p>
        </div>
      </Card>

      <Card>
        <div class="flex flex-wrap items-center gap-2 p-6 pb-3">
          <div class="text-base font-semibold leading-none tracking-tight">性能</div>
          <span class="text-xs text-muted-foreground">
            {{ metricsSupported ? met!.cores + " 核 · 已运行 " + fmtUptime(met!.uptime_secs) : met ? "本机不可采集" : "采集中…" }}
          </span>
          <div class="flex-1" />
          <span class="text-xs text-muted-foreground">每 3 秒刷新</span>
        </div>
        <div v-if="!metricsSupported" class="px-4 pb-4 pt-0 text-xs text-muted-foreground md:px-6 md:pb-6">
          当前平台不支持采集（性能指标读取的是 Linux 的 /proc；Windows 桌面端请在服务器上查看）
        </div>
        <div v-else class="grid grid-cols-1 gap-3 px-4 pb-4 pt-0 sm:grid-cols-2 md:px-6 md:pb-6">
          <div class="rounded-lg border p-3">
            <div class="flex items-center justify-between text-xs">
              <span class="font-medium">CPU</span>
              <span class="tabular-nums text-muted-foreground">{{ met ? Math.round(met.cpu_pct) + "%" : "-" }}</span>
            </div>
            <div class="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div
                class="h-full rounded-full bg-primary transition-all"
                :style="{ width: (met ? met.cpu_pct : 0) + '%' }"
              />
            </div>
            <svg viewBox="0 0 240 40" class="mt-2 h-10 w-full" preserveAspectRatio="none">
              <polyline :points="cpuSpark" fill="none" stroke="currentColor" stroke-width="1.5" class="text-primary" />
            </svg>
          </div>

          <div class="rounded-lg border p-3">
            <div class="flex items-center justify-between text-xs">
              <span class="font-medium">内存</span>
              <span class="tabular-nums text-muted-foreground">
                {{ met ? fmtSize(met.mem_total_kb - met.mem_avail_kb) + " / " + fmtSize(met.mem_total_kb) : "-" }}
              </span>
            </div>
            <div class="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div class="h-full rounded-full bg-emerald-500 transition-all" :style="{ width: memPct + '%' }" />
            </div>
            <div class="mt-2 flex items-center justify-between text-xs text-muted-foreground">
              <span>磁盘</span>
              <span class="tabular-nums">
                {{ met ? fmtSize(met.disk_used_kb) + " / " + fmtSize(met.disk_total_kb) : "-" }}
              </span>
            </div>
            <div class="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div class="h-full rounded-full bg-amber-500 transition-all" :style="{ width: diskPct + '%' }" />
            </div>
          </div>

          <div class="rounded-lg border p-3 text-xs sm:col-span-2">
            <div class="grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-4">
              <div class="flex items-center justify-between gap-2">
                <span class="text-muted-foreground">负载 1/5/15</span>
                <span class="tabular-nums">
                  {{ met && met.load1 >= 0 ? met.load1.toFixed(2) + " / " + met.load5.toFixed(2) + " / " + met.load15.toFixed(2) : "-" }}
                </span>
              </div>
              <div class="flex items-center justify-between gap-2">
                <span class="text-muted-foreground">下行</span>
                <span class="tabular-nums">{{ met ? fmtRate(met.rx_bps) : "-" }}</span>
              </div>
              <div class="flex items-center justify-between gap-2">
                <span class="text-muted-foreground">上行</span>
                <span class="tabular-nums">{{ met ? fmtRate(met.tx_bps) : "-" }}</span>
              </div>
              <div class="flex items-center justify-between gap-2">
                <span class="text-muted-foreground">面板占用</span>
                <span class="tabular-nums">{{ met ? fmtSize(met.panel_rss_kb) : "-" }}</span>
              </div>
            </div>
          </div>
        </div>
      </Card>

      <Card>
        <div class="flex flex-wrap items-center gap-2 p-6 pb-3">
          <div class="text-base font-semibold leading-none tracking-tight">转发规则</div>
          <span class="text-xs text-muted-foreground">{{ filtered.length }} / {{ rules.length }} 条</span>
          <div class="flex-1" />
          <div class="relative">
            <Search class="pointer-events-none absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input v-model="query" class="w-56 pl-8" placeholder="搜索域名 / 目标 / 备注" />
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
                <th class="h-9 w-44 px-2 text-left align-middle text-xs font-medium text-muted-foreground">操作</th>
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
                  <div class="flex gap-1">
                    <Button variant="outline" size="icon" title="编辑" @click="openEdit(r)">
                      <Pencil class="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="outline" size="icon" title="上移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), -1)">
                      <ArrowUp class="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="outline" size="icon" title="下移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), 1)">
                      <ArrowDown class="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="outline" size="icon" title="删除" @click="remove(r.hostname)">
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
                <Button variant="outline" size="icon" title="编辑" @click="openEdit(r)">
                  <Pencil class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" title="上移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), -1)">
                  <ArrowUp class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" title="下移" @click="move(rules.findIndex((x) => x.hostname === r.hostname), 1)">
                  <ArrowDown class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" title="删除" @click="remove(r.hostname)">
                  <Trash2 class="h-3.5 w-3.5 text-red-600" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </Card>

      <Card>
        <div class="flex flex-wrap items-center gap-2 p-6 pb-3">
          <div class="text-base font-semibold leading-none tracking-tight">日志</div>
          <span class="text-xs text-muted-foreground">共 {{ totalLogs }} 条, 显示最近 {{ visibleLogs.length }} 条</span>
          <div class="flex-1" />
          <div class="relative">
            <select
              v-model.number="logLimit"
              class="h-8 appearance-none rounded-md border border-input bg-background pl-2 pr-7 text-xs transition-colors hover:bg-accent"
            >
              <option :value="50">50 条</option>
              <option :value="100">100 条</option>
              <option :value="200">200 条</option>
              <option :value="0">全部</option>
            </select>
            <ChevronDown class="pointer-events-none absolute right-1.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
          </div>
        </div>
        <div class="p-6 pt-0">
          <pre ref="logEl" class="h-40 overflow-auto rounded-lg bg-slate-900 p-3 text-xs leading-relaxed text-slate-200 md:h-52">{{ logText }}</pre>
        </div>
      </Card>
    </main>

    <Transition name="pop">
      <div v-if="showForm" class="fixed inset-0 z-20 flex items-center justify-center bg-black/40 p-4">
        <div class="max-h-[90vh] w-full max-w-lg overflow-auto rounded-lg border bg-card p-4 shadow-xl md:p-6">
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
                  <select
                    id="f-scheme"
                    v-model="form.scheme"
                    class="h-9 w-full appearance-none rounded-md border border-input bg-background pl-3 pr-9 text-sm transition-colors hover:bg-accent"
                  >
                    <option value="http">http</option>
                    <option value="https">https</option>
                  </select>
                  <ChevronDown class="pointer-events-none absolute right-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                </div>
              </div>
              <div class="flex flex-col justify-end gap-2 pb-1 text-xs">
                <label class="flex items-center gap-2">
                  <input v-model="form.noTlsVerify" type="checkbox" />
                  忽略源站证书
                </label>
                <label class="flex items-center gap-2">
                  <input v-model="form.enabled" type="checkbox" />
                  启用
                </label>
              </div>
            </div>

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
        </div>
      </div>
    </Transition>

    <Transition name="pop">
      <div v-if="showTunnelToken" class="fixed inset-0 z-20 flex items-center justify-center bg-black/40 p-4">
        <div class="max-h-[90vh] w-full max-w-lg overflow-auto rounded-lg border bg-card p-4 shadow-xl md:p-6">
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
        </div>
      </div>
    </Transition>

    <Transition name="pop">
      <div v-if="showToken" class="fixed inset-0 z-20 flex items-center justify-center bg-black/40 p-4">
        <div class="max-h-[90vh] w-full max-w-lg overflow-auto rounded-lg border bg-card p-4 shadow-xl md:p-6">
          <div class="mb-4 flex items-center justify-between">
            <div class="text-base font-semibold">Cloudflare API Token</div>
            <button class="text-muted-foreground hover:text-foreground" @click="showToken = false">
              <X class="h-4 w-4" />
            </button>
          </div>
          <div class="space-y-3">
            <div class="flex items-center gap-2 text-sm">
              <Badge :variant="hasToken ? 'success' : 'muted'">{{ hasToken ? "已配置" : "未配置" }}</Badge>
              <span class="text-xs text-muted-foreground">只用于自动写 DNS; 不配置也能正常转发</span>
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
              <Input id="cf" v-model="tokenInput" type="password" placeholder="Zone:DNS:Edit 权限的 Token" />
            </div>
            <div class="flex justify-end gap-2 pt-1">
              <Button variant="outline" type="button" :disabled="tokenBusy || !hasToken" @click="clearToken">清除</Button>
              <Button type="button" :disabled="tokenBusy" @click="saveToken">保存</Button>
            </div>
          </div>
        </div>
      </div>
    </Transition>

    <div
      v-if="toast"
      class="fixed bottom-5 right-5 z-30 max-w-sm rounded-lg px-4 py-2.5 text-sm text-white shadow-lg"
      :class="toast.bad ? 'bg-red-600' : 'bg-slate-900'"
    >
      {{ toast.text }}
    </div>
  </div>
</template>
