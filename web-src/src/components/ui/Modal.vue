<script setup lang="ts">
import { nextTick, onUnmounted, ref, watch } from 'vue';
const model = defineModel<boolean>({default:false});
const props = defineProps<{label: string; busy?: boolean}>();
const dialog = ref<HTMLElement>();
let previous: HTMLElement | null = null;
let oldOverflow = '';
function close() { if (!props.busy) model.value = false; }
function key(e: KeyboardEvent) {
  if (!model.value || e.defaultPrevented || Array.from(document.querySelectorAll('[role=dialog]')).slice(-1)[0] !== dialog.value) return;
  if (e.key === 'Escape' && !document.querySelector('[role="listbox"]')) { e.preventDefault(); close(); }
  if (e.key !== 'Tab') return;
  const items = [...(dialog.value?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), textarea, a[href], summary, [tabindex="0"]') || [])].filter(el => el.getClientRects().length);
  const first = items[0], last = items[items.length - 1];
  if (!first) { e.preventDefault(); dialog.value?.focus(); }
  else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}
watch(model, async open => {
  if (open) {
    previous = document.activeElement as HTMLElement; oldOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden'; document.addEventListener('keydown', key);
    await nextTick(); dialog.value?.focus();
  } else {
    document.body.style.overflow = oldOverflow; document.removeEventListener('keydown', key); previous?.focus();
  }
});
onUnmounted(() => { document.removeEventListener('keydown', key); if(model.value) document.body.style.overflow = oldOverflow; });
</script>
<template>
  <Teleport to="body"><Transition name="pop"><div v-if="model" class="fixed inset-0 z-30 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm" @click.self="close"><section ref="dialog" tabindex="-1" role="dialog" aria-modal="true" :aria-label="label" class="max-h-[90dvh] w-full max-w-2xl overflow-auto rounded-xl border bg-card p-5 text-foreground shadow-xl outline-none sm:p-6"><slot /></section></div></Transition></Teleport>
</template>
