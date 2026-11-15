<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, useId } from 'vue';
import { Check, ChevronDown } from 'lucide-vue-next';
const props = defineProps<{ modelValue: string | number; options: {value: string | number; label: string}[]; label?: string; disabled?: boolean; id?: string }>();
const emit = defineEmits<{ 'update:modelValue': [value: any] }>();
const root = ref<HTMLElement>();
const trigger = ref<HTMLButtonElement>();
const open = ref(false);
const active = ref(0);
const uid = useId();
const selected = computed(() => props.options.find(o => o.value === props.modelValue)?.label || '请选择');
async function toggle() {
  open.value = !open.value;
  active.value = Math.max(0, props.options.findIndex(o => o.value === props.modelValue));
  await nextTick();
  if (open.value) root.value?.querySelector<HTMLElement>('[role=listbox]')?.focus();
}
function choose(index: number) {
  if (!props.options[index]) return;
  emit('update:modelValue', props.options[index].value);
  open.value = false;
  trigger.value?.focus();
}
function key(event: KeyboardEvent) {
  if (event.key === 'Escape') { open.value = false; trigger.value?.focus(); }
  else if (event.key === 'Tab') open.value = false;
  else if (['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' '].includes(event.key)) {
    event.preventDefault();
    if (event.key === 'Enter' || event.key === ' ') choose(active.value);
    else active.value = event.key === 'Home' ? 0 : event.key === 'End' ? props.options.length - 1 : (active.value + (event.key === 'ArrowDown' ? 1 : -1) + props.options.length) % props.options.length;
    nextTick(() => document.getElementById(`${uid}-${active.value}`)?.scrollIntoView({block: 'nearest'}));
  } else if (event.key.length === 1) {
    const found = props.options.findIndex(o => o.label.toLowerCase().startsWith(event.key.toLowerCase()));
    if (found >= 0) active.value = found;
  }
}
function outside(event: PointerEvent) { if (!root.value?.contains(event.target as Node)) open.value = false; }
onMounted(() => document.addEventListener('pointerdown', outside));
onUnmounted(() => document.removeEventListener('pointerdown', outside));
</script>
<template>
  <div ref="root" class="select-root">
    <button :id="id" ref="trigger" type="button" class="select-trigger" :disabled="disabled" :aria-label="label" aria-haspopup="listbox" :aria-expanded="open" :aria-controls="uid" @click="toggle" @keydown.down.prevent="!open && toggle()">
      <span class="truncate">{{ selected }}</span><ChevronDown class="h-4 w-4 shrink-0 text-muted-foreground" />
    </button>
    <ul v-if="open" :id="uid" role="listbox" tabindex="-1" :aria-label="label" :aria-activedescendant="`${uid}-${active}`" class="select-options" @keydown="key">
      <li v-for="(opt, index) in options" :id="`${uid}-${index}`" :key="opt.value" role="option" :aria-selected="modelValue === opt.value" :class="{active: active === index}" @pointermove="active = index" @click="choose(index)">
        <span>{{ opt.label }}</span><Check v-if="modelValue === opt.value" class="h-4 w-4" />
      </li>
    </ul>
  </div>
</template>
