<script setup lang="ts">
import { cn } from "@/lib/utils";
import { computed } from "vue";

const props = defineProps<{ class?: string }>();
const classes = computed(() => cn("rounded-[20px] border border-border/70 bg-card text-card-foreground", props.class));
</script>

<template>
  <div :class="classes"><slot /></div>
</template>
