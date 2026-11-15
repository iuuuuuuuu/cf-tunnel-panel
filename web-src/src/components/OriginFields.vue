<script setup lang="ts">
import type { OriginSettings } from '@/api';
import Switch from '@/components/ui/Switch.vue';
const model = defineModel<OriginSettings>({required: true});
defineProps<{scheme: string}>();
const durations = [{key:'connectTimeout', label:'连接超时', hint:'30s'}, {key:'tlsTimeout', label:'TLS 握手超时', hint:'10s'}, {key:'tcpKeepAlive', label:'TCP 保活间隔', hint:'30s'}, {key:'keepAliveTimeout', label:'空闲连接超时', hint:'1m30s'}] as const;
</script>
<template>
  <div class="space-y-4">
    <Switch v-model="model.http2Origin" label="HTTP/2 回源" description="源站需支持 HTTPS + HTTP/2。不会改变访客到边缘的协议。" :disabled="scheme !== 'https'" />
    <Switch v-model="model.disableChunkedEncoding" label="禁用分块传输" description="默认关闭；仅在源站不兼容 HTTP/1.1 chunked 请求时启用。" />
    <div class="grid grid-cols-2 gap-3">
      <label v-for="field in durations" :key="field.key" class="field-label">{{ field.label }}<input v-model="model[field.key]" class="field-input" :placeholder="field.hint" required /></label>
      <label class="field-label">最大空闲连接数<input v-model.number="model.keepAliveConnections" class="field-input" type="number" min="0" max="10000" required /></label>
      <label class="field-label">Host 请求头<input v-model="model.httpHostHeader" class="field-input" placeholder="默认使用请求域名" /></label>
      <label class="field-label col-span-2">TLS 服务名称（SNI）<input v-model="model.originServerName" class="field-input" placeholder="默认使用源站 URL 的主机名" /></label>
    </div>
    <p class="text-xs leading-relaxed text-muted-foreground">时长支持 30s、1m30s 等格式。这些是建立连接和空闲连接参数，不是模型生成时间上限。</p>
  </div>
</template>
