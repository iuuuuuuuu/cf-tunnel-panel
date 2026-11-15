<script setup lang="ts">
const model = defineModel<boolean>({default: false});
defineProps<{ label: string; description?: string; disabled?: boolean }>();
</script>
<template>
  <label class="switch-row" :class="{ 'opacity-50': disabled }">
    <span><span class="block text-sm font-medium">{{ label }}</span><span v-if="description" class="mt-1 block text-xs leading-relaxed text-muted-foreground">{{ description }}</span></span>
    <input v-model="model" class="switch-input" type="checkbox" role="switch" :disabled="disabled" :aria-label="label" />
  </label>
</template>
