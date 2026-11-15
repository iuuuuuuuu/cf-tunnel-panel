// Runs only inside the authenticated, same-origin diagnostic iframe.
// Its CSP allows HTTPS connections only to the current forwarding-rule hostnames.
(() => {
  let controller;
  const channel = 'cftp-access-probe-v1';
  const announce = payload => parent.postMessage({ channel, ...payload }, location.origin);
  const allowed = new Set();
  async function initialize() {
    try {
      const response = await fetch('/api/state', { cache: 'no-store' });
      if (!response.ok) throw new Error('会话不可用');
      const state = await response.json();
      for (const rule of state.rules) allowed.add('https://' + rule.hostname);
      announce({ kind: 'ready' });
    } catch { announce({ kind: 'unavailable', error: '诊断初始化失败，请刷新面板后重试。' }); }
  }
  addEventListener('message', async event => {
    if (event.source !== parent || event.origin !== location.origin || event.data?.channel !== channel) return;
    if (event.data.kind === 'cancel') { controller?.abort(); return; }
    if (event.data.kind !== 'sample') return;
    controller?.abort();
    const { id, url: target, timeoutMs } = event.data;
    let url;
    try {
      url = new URL(target);
      if (!allowed.has(url.origin) || url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error();
    } catch { announce({ kind: 'result', id, error: '只能测试转发规则中的 HTTPS 公网域名。' }); return; }
    const abort = new AbortController();
    controller = abort;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; abort.abort(); }, Math.min(20000, Math.max(1000, timeoutMs || 10000)));
    const start = performance.now();
    try {
      const response = await fetch(url.href, {
        mode: 'no-cors', credentials: 'omit', cache: 'no-store', redirect: 'follow',
        referrerPolicy: 'no-referrer', signal: abort.signal,
      });
      const elapsedMs = performance.now() - start;
      // Stop after headers so large downloads/SSE do not keep running.
      if (response.body) await response.body.cancel();
      // Resource Timing can arrive after fetch resolves; never reuse a previous sample.
      abort.abort();
      await new Promise(resolve => setTimeout(resolve, 75));
      const entry = performance.getEntriesByName(url.href).filter(e =>
        e.entryType === 'resource' && e.startTime >= start && e.startTime <= start + elapsedMs
      ).at(-1);
      const detailed = entry && entry.requestStart > 0 && entry.responseStart > 0;
      const opaque = response.type === 'opaque' || response.type === 'opaqueredirect';
      announce({ kind: 'result', id, elapsedMs, received: true,
        status: opaque ? null : response.status,
        timing: detailed ? {
          dnsMs: entry.domainLookupEnd - entry.domainLookupStart,
          connectMs: entry.connectEnd - entry.connectStart,
          tlsMs: entry.secureConnectionStart > 0 ? entry.connectEnd - entry.secureConnectionStart : null,
          ttfbMs: entry.responseStart - entry.requestStart,
          protocol: entry.nextHopProtocol || null,
        } : null,
      });
    } catch {
      announce({ kind: 'result', id, elapsedMs: performance.now() - start, received: false,
        error: timedOut ? '超过等待时间' : abort.signal.aborted ? '已取消' : '网络、证书、跨域跳转或浏览器策略阻止了请求',
      });
    } finally { abort.abort(); clearTimeout(timer); if (controller === abort) controller = undefined; }
  });
  initialize();
})();
