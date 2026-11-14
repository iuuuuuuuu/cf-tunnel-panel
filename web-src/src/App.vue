<script setup lang="ts">
import Login from "@/pages/Login.vue";
import PanelPage from "@/pages/Panel.vue";

const isLogin = window.location.pathname === "/login";
</script>

<template>
  <Login v-if="isLogin" />
  <PanelPage v-else />
</template>
