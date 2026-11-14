export type Rule = {
  hostname: string;
  port: number;
  service: string;
  host: string;
  scheme: string;
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
  noTlsVerify?: boolean;
  enabled?: boolean;
  note?: string;
};

export type Tunnel = { id: string; name: string };

export type State = {
  tunnel: string;
  tunnels: Tunnel[];
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
