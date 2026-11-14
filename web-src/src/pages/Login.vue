<script setup lang="ts">
import { ref } from "vue";
import Button from "@/components/ui/Button.vue";
import Card from "@/components/ui/Card.vue";
import Input from "@/components/ui/Input.vue";
import Label from "@/components/ui/Label.vue";
import { LockKeyhole, Loader2 } from "lucide-vue-next";

const password = ref("");
const token = ref("");
const error = ref("");
const busy = ref(false);

async function onSubmit() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const resp = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password.value, token: token.value }),
    });
    if (resp.ok) {
      window.location.href = "/";
      return;
    }
    if (resp.status === 429) error.value = "失败次数过多，请稍后再试";
    else if (resp.status === 401) error.value = "口令或访问令牌不正确";
    else error.value = "登录失败（HTTP " + resp.status + "）";
  } catch (e) {
    error.value = "网络错误，请重试";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="flex min-h-full items-center justify-center bg-slate-50 p-6">
    <Card class="w-[380px]">
      <div class="p-6 pb-3">
        <div class="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
          <LockKeyhole class="h-4 w-4 text-primary" />
        </div>
        <div class="text-base font-semibold leading-none tracking-tight">内网穿透面板</div>
        <div class="mt-1.5 text-sm text-muted-foreground">需要口令 + 访问令牌两项</div>
      </div>
      <div class="p-6 pt-0">
        <form class="space-y-4" @submit.prevent="onSubmit">
          <div class="space-y-1.5">
            <Label for="pw">口令</Label>
            <Input id="pw" v-model="password" type="password" autocomplete="current-password" required />
          </div>
          <div class="space-y-1.5">
            <Label for="tk">访问令牌</Label>
            <Input id="tk" v-model="token" type="password" autocomplete="off" required />
          </div>
          <p v-if="error" class="rounded-md bg-red-50 px-3 py-2 text-sm text-red-600">{{ error }}</p>
          <Button type="submit" class="w-full" :disabled="busy">
            <Loader2 v-if="busy" class="h-4 w-4 animate-spin" />
            登录
          </Button>
        </form>
      </div>
    </Card>
  </div>
</template>
