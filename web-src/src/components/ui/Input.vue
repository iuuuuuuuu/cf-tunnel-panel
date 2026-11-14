<script setup lang="ts">
import { cn } from "@/lib/utils";

const model = defineModel<string>({ default: "" });
withDefaults(
  defineProps<{ type?: string; placeholder?: string; id?: string; required?: boolean; autocomplete?: string; class?: string }>(),
  { type: "text" }
);
</script>

<template>
  <input
    :id="id"
    v-model="model"
    :type="type"
    :placeholder="placeholder"
    :required="required"
    :autocomplete="autocomplete"
    :class="
      cn(
        'flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50',
        $props.class
      )
    "
  />
</template>
