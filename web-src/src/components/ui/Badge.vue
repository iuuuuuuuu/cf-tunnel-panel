<script setup lang="ts">
import { computed } from "vue";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        outline: "text-foreground",
        success: "border-transparent bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
        warning: "border-transparent bg-amber-500/10 text-amber-700 dark:text-amber-400",
        destructive: "border-transparent bg-red-500/10 text-red-700 dark:text-red-400",
        muted: "border-transparent bg-muted text-muted-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

type Variants = VariantProps<typeof badgeVariants>;
const props = withDefaults(defineProps<{ variant?: Variants["variant"] }>(), { variant: "default" });
const classes = computed(() => cn(badgeVariants({ variant: props.variant })));
</script>

<template>
  <div :class="classes"><slot /></div>
</template>
