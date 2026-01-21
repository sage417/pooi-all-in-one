<template>
  <n-message-provider>
    <div class="app-container">
      <router-view />
    </div>
  </n-message-provider>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { useDeviceStore } from '@/stores/devices';
import { useSignalStore } from '@/stores/signal'
import { NMessageProvider } from 'naive-ui'
import { ControlledEndpoint } from '@/services/endpoint';
import { useRouter, useRoute } from 'vue-router';

const deviceStore = useDeviceStore()
const signalStore = useSignalStore()
const router = useRouter()
const route = useRoute()

let endpoint: ControlledEndpoint | null

onMounted(async () => {
  console.log('👋 This message is being logged by "App.vue", included via Vite');

  const deviceId = await window.electronAPI.ipcRendererInvoke('device-fingerprint')
  deviceStore.setDeviceId(deviceId)
  // init signal server
  signalStore.initialize('http://192.168.2.122:8080/ws')

  if (route.name == 'devices') {
    console.log('start endpoint')
    endpoint = new ControlledEndpoint()
    await endpoint.start()
  }
})

onUnmounted(() => {
  endpoint?.close()
  signalStore.close()
})
</script>
