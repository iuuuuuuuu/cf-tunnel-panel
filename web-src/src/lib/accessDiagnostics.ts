import { median, quantile } from 'simple-statistics';
import { useStorage } from '@vueuse/core';
import { nanoid } from 'nanoid';

export type ProbeTiming = { dnsMs:number; connectMs:number; tlsMs:number|null; ttfbMs:number; protocol:string|null };
export type ProbeSample = { elapsedMs:number; received:boolean; status:number|null; timing:ProbeTiming|null; error?:string };
export type AccessReport = {
  runId:string; mode:'browser'|'server'; hostname:string; path:string; url:string; profile:string; at:string;
  samples:ProbeSample[]; count:number; timeoutMs:number; finished:boolean;
  connection:{protocol:string;'edge-ip-version':string;region:string};
};
export type AccessRun = {id:string;label:string;network:string;source:'current-device-browser'|'panel-server';at:string;results:AccessReport[]};
export const newRunId = () => nanoid();
// Per-browser and per-panel storage; reloads and switching networks keep recent rounds.
export const accessReports = useStorage<AccessRun[]>('cftp-diagnostics-v2',[],localStorage,{onError:()=>{},mergeDefaults:false});
if (!Array.isArray(accessReports.value)) accessReports.value=[];
accessReports.value=accessReports.value.filter(r=>typeof r?.id==='string'&&Array.isArray(r.results)).slice(-30);
export function summarize(samples:ProbeSample[]) {
  const good=samples.filter(s=>s.received&&Number.isFinite(s.elapsedMs)&&s.elapsedMs>=0);
  const times=good.map(s=>s.elapsedMs);
  return {received:times.length,failed:samples.length-times.length,medianMs:times.length?median(times):null,
    minMs:times.length?Math.min(...times):null,maxMs:times.length?Math.max(...times):null,
    spreadMs:times.length>1?quantile(times,.75)-quantile(times,.25):null};
}
export function diagnosticUrl(hostname:string,path:string):string {
  if(!path.startsWith('/')||path.startsWith('//')||/[\\\s?#\u0000-\u001f]/u.test(path)) throw new Error('填写 / 开头的公开只读路径，不含查询参数、空格或 #。例如 /login、/health、/assets/app.js。');
  const url=new URL('https://'+hostname+path);
  if(url.hostname!==hostname.toLowerCase()||url.port||url.username||url.password)throw new Error('公网域名不合法');
  return url.href;
}
export function comparable(a:AccessReport,b:AccessReport) {
  return a.hostname===b.hostname&&a.path===b.path&&a.profile===b.profile&&a.mode===b.mode&&a.count===b.count&&a.timeoutMs===b.timeoutMs;
}
export function complete(report:AccessReport) {
  const stats=summarize(report.samples);
  return report.finished&&report.samples.length===report.count&&stats.failed===0&&stats.received===report.count;
}
export const milliseconds=(value:number|null)=>value===null?'不可读取':Math.round(value).toLocaleString()+' ms';
