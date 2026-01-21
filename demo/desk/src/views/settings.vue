<template>
    <h1>💖 Hello World!</h1>
    <p>Welcome to your Electron application.</p>
  </template>
  
  <script setup lang="ts">
  import { ref, onMounted ,nextTick } from 'vue'
  onMounted(() => {
    console.log('👋 This message is being logged by "App.vue", included via Vite');
  })
  </script>