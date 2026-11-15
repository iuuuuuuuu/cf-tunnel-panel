<script setup lang="ts">
import { Monitor, Moon, Sun } from 'lucide-vue-next';
import { theme, setTheme, type Theme } from '@/lib/theme';
const options = [{value: 'system', label: '跟随系统', icon: Monitor}, {value: 'light', label: '浅色', icon: Sun}, {value: 'dark', label: '深色', icon: Moon}] as const;
</script>
<template>
  <div class="theme-picker" role="group" aria-label="外观主题">
    <button v-for="opt in options" :key="opt.value" type="button" :title="opt.label" :aria-label="opt.label" :aria-pressed="theme === opt.value" @click="setTheme(opt.value as Theme)">
      <component :is="opt.icon" class="h-4 w-4" />
    </button>
  </div>
</template>
