<script setup lang="ts">
import { computed } from "vue";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow-sm hover:bg-primary/90",
        secondary: "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        outline: "border border-input bg-background hover:bg-accent hover:text-accent-foreground",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        destructive: "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-10 rounded-md px-6",
        icon: "h-8 w-8",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  }
);

type Variants = VariantProps<typeof buttonVariants>;

const props = withDefaults(
  defineProps<{ variant?: Variants["variant"]; size?: Variants["size"]; type?: "button" | "submit" }>(),
  { variant: "default", size: "default", type: "button" }
);

const classes = computed(() => cn(buttonVariants({ variant: props.variant, size: props.size })));
</script>

<template>
  <button :type="type" :class="classes" v-bind="$attrs">
    <slot />
  </button>
</template>

<script lang="ts">
export default { inheritAttrs: false };
</script>
