<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import * as echarts from 'echarts/core';
import { BarChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { theme } from '@/lib/theme';
import { summarize, complete, comparable, type AccessRun, type AccessReport } from '@/lib/accessDiagnostics';
echarts.use([BarChart,CanvasRenderer,GridComponent,TooltipComponent,LegendComponent]);
const props=defineProps<{rows:{run:AccessRun;report:AccessReport}[]}>();const el=ref<HTMLElement>();let chart:echarts.ECharts|undefined;let observer:ResizeObserver|undefined;
const usable=computed(()=>{const first=props.rows.find(row=>complete(row.report));return props.rows.filter(row=>complete(row.report)&&first&&row.report.profile===first.report.profile&&row.report.count===first.report.count&&row.report.timeoutMs===first.report.timeoutMs)});
function render(){if(!chart)return;const narrow=(el.value?.clientWidth??600)<400;const fg=document.documentElement.classList.contains('dark')?'#b7c9c2':'#607572';chart.setOption({animation:false,grid:{left:12,right:24,top:38,bottom:20,containLabel:true},tooltip:{trigger:'axis',confine:true,renderMode:'richText'},legend:{top:0,textStyle:{color:fg}},xAxis:{type:'value',name:'ms',splitNumber:3,axisLabel:{color:fg,hideOverlap:true,fontSize:10},splitLine:{lineStyle:{color:'#88888820'}}},yAxis:{type:'category',inverse:true,data:usable.value.map(row=>row.run.label+' · '+row.run.network),axisLabel:{color:fg,width:narrow?65:140,overflow:'truncate',fontSize:10}},series:[{name:'当前设备浏览器',type:'bar',itemStyle:{color:'#17977a',borderRadius:[0,5,5,0]},data:usable.value.map(row=>row.run.source==='current-device-browser'?summarize(row.report.samples).medianMs:null)},{name:'面板主机内部',type:'bar',itemStyle:{color:'#d49443',borderRadius:[0,5,5,0]},data:usable.value.map(row=>row.run.source==='panel-server'?summarize(row.report.samples).medianMs:null)}]},true)}
watch(()=>[props.rows,theme.value],()=>setTimeout(render,0),{deep:true});onMounted(()=>{if(!el.value)return;chart=echarts.init(el.value,undefined,{renderer:'canvas'});observer=new ResizeObserver(()=>{chart?.resize();render()});observer.observe(el.value);render()});onUnmounted(()=>{observer?.disconnect();chart?.dispose()});
</script>
<template><div ref="el" class="run-comparison" role="img" aria-label="多轮网络响应耗时对比图"/><p v-if="!usable.length" class="text-xs text-muted-foreground">没有完整可比较的结果，超时或未完成采样不会被当作更快线路。</p></template>
