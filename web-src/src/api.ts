export type OriginSettings = {
  connectTimeout: string; tlsTimeout: string; tcpKeepAlive: string; keepAliveTimeout: string;
  keepAliveConnections: number; http2Origin: boolean; disableChunkedEncoding: boolean;
  httpHostHeader: string; originServerName: string;
};
export const defaultOrigin = (): OriginSettings => ({connectTimeout:'30s', tlsTimeout:'10s', tcpKeepAlive:'30s', keepAliveTimeout:'1m30s', keepAliveConnections:100, http2Origin:false, disableChunkedEncoding:false, httpHostHeader:'', originServerName:''});
export type ConnectionSettings = { protocol: string; 'edge-ip-version': string; region: string; loglevel: string };
export type Rule = {
  hostname: string;
  port: number;
  service: string;
  host: string;
  scheme: string;
  origin: OriginSettings;
  noTlsVerify: boolean;
  enabled: boolean;
  note: string;
  port_open?: boolean;
};

export type ScannedService = { port: number; addr: string; process: string };

export type Metrics = {
  cpu_pct: number;
  cores: number;
  mem_total_kb: number;
  mem_avail_kb: number;
  disk_total_kb: number;
  disk_used_kb: number;
  load1: number;
  load5: number;
  load15: number;
  uptime_secs: number;
  rx_bps: number;
  tx_bps: number;
  panel_rss_kb: number;
};

export type RuleInput = {
  hostname: string;
  port: number;
  service?: string;
  host?: string;
  scheme?: string;
  origin?: OriginSettings;
  noTlsVerify?: boolean;
  enabled?: boolean;
  note?: string;
};

export type Tunnel = { id: string; name: string };

export type State = {
  connection: ConnectionSettings;
  tunnel: string;
  tunnels: Tunnel[];
  tunnels_error?: string | null;
  rules: Rule[];
  running: boolean;
  external: boolean;
  conn: string;
  config_path: string;
  has_cf_token: boolean;
  cf_token_path: string;
  has_tunnel_token: boolean;
  tunnel_token_path: string;
  logs: string[];
  csrf: string;
};

let csrf = "";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (init.method && init.method !== "GET") headers.set("X-CSRF", csrf);

  const resp = await fetch(path, Object.assign({}, init, { headers }));
  if (resp.status === 401) {
    window.location.href = "/login";
    throw new ApiError("未登录", 401);
  }
  const text = await resp.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
  if (!resp.ok) throw new ApiError(data.error || "HTTP " + resp.status, resp.status);
  return data as T;
}

export function setCsrf(token: string) {
  csrf = token;
}

export const api = {
  cloud: (body: Record<string, string>) => request<{ok?: boolean; zone?: string; settings?: Record<string, {value: string; editable: boolean}>}>('/api/cloud', {method:'POST', body:JSON.stringify(body)}),
  setConnection: (settings: ConnectionSettings) => request<{ok: boolean}>('/api/connection', {method:'POST', body:JSON.stringify(settings)}),
  optimize: (input:Optimization) => request<{ok:boolean;output:string;restarted?:boolean}>("/api/optimization/apply",{method:"POST",body:JSON.stringify(input)}),
  state: () => request<State>("/api/state"),
  setRules: (rules: RuleInput[]) =>
    request<{ ok: boolean }>("/api/rules", { method: "POST", body: JSON.stringify({ rules }) }),
  setTunnel: (id: string) =>
    request<{ ok: boolean }>("/api/tunnel", { method: "POST", body: JSON.stringify({ id }) }),
  save: () =>
    request<{ ok: boolean; output?: string; restarted?: boolean }>("/api/save", {
      method: "POST",
      body: "{}",
    }),
  start: () => request<{ ok: boolean; output?: string }>("/api/start", { method: "POST", body: "{}" }),
  stop: () => request<{ ok: boolean }>("/api/stop", { method: "POST", body: "{}" }),
  syncDns: () => request<{ ok: boolean; messages: string[] }>("/api/dns", { method: "POST", body: "{}" }),
  scan: () => request<{ services: ScannedService[] }>("/api/scan"),
  metrics: () => request<Metrics>("/api/metrics"),
  metricHistory: (from:string,to:string) => request<{samples:MetricsSample[];from:number;to:number;downsampled:boolean;total:number;storage_error:string|null}>(`/api/metrics/history?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`),
  alerts: (from?:string,to?:string) => request<AlertSettings>("/api/alerts"+(from&&to?`?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`:"")),
  saveAlerts: (input:AlertConfigInput) => request<{ok:boolean}>("/api/alerts/config",{method:"POST",body:JSON.stringify(input)}),
  testAlert: () => request<{ok:boolean}>("/api/alerts/test",{method:"POST",body:"{}"}),
  serverDiagnostic: (url:string, timeout_ms=10000, signal?:AbortSignal) => request<ServerDiagnostic>("/api/diagnostics/server",{method:"POST",body:JSON.stringify({url,timeout_ms}),signal}),
  setTunnelToken: (token: string) =>
    request<{ ok: boolean; has_token: boolean }>("/api/tunnel-token", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  setCfToken: (token: string) =>
    request<{ ok: boolean; has_token: boolean }>("/api/cf-token", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  logout: async () => {
    await fetch("/logout", { method: "POST", headers: { "X-CSRF": csrf } });
    window.location.href = "/login";
  },
};

export type MetricsSample = Omit<Metrics,'cpu_pct'|'rx_bps'|'tx_bps'> & {at:number;cpu_pct:number|null;rx_bps:number|null;tx_bps:number|null};
export type AlertEvent={at:number;level:string;message:string;channel:string|null};
export type AlertSettings={thresholds:{cpu_pct:number;memory_pct:number;disk_pct:number;duration_seconds:number;cooldown_seconds:number};pushplus_enabled:boolean;pushplus_configured:boolean;channels:{id:string;label:string;supported:boolean}[];active:string[];log:AlertEvent[];from:number;to:number;total:number;truncated:boolean;storage_error:string|null};
export type AlertConfigInput={cpu_pct:number;memory_pct:number;disk_pct:number;pushplus_enabled:boolean;pushplus_token?:string;clear_pushplus_token?:boolean};
export type ServerDiagnostic={source:'panel-server';server:string;elapsed_ms:number;status:number|null;timing?:{dnsMs:number;connectMs:number;tlsMs:number|null;ttfbMs:number;protocol:string|null}|null;error:string|null;measured:string};
export type Optimization={action:'connection'|'bypass';confirmed:boolean;settings?:ConnectionSettings;before?:ConnectionSettings;restart?:boolean;hostname?:string;prefix?:string};
