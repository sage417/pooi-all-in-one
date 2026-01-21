<template>
  <div class="devices-container">

    <n-button type="primary" @click="refreshDevices" :loading="deviceStore.loading">
      <n-icon :component="Refresh"> </n-icon>
      刷新列表
    </n-button>
    <n-spin :show="deviceStore.loading">
      <n-empty v-if="!deviceStore.loading && deviceStore.getDevices.length === 0" description="暂无可用设备">
        <template #extra>
          <n-button @click="refreshDevices">刷新</n-button>
        </template>
      </n-empty>

      <div v-else class="devices-grid">
        <n-card v-for="device in deviceStore.getDevices" :key="device.id" class="device-card" :bordered="false"
          @click="connectToDevice(device)">
          <template #cover>
            <div class="device-icon">
              <n-icon :component="getDeviceIcon(device.os)" size="48" />
            </div>
          </template>
          <div class="device-info">
            <div class="device-name">{{ device.name }}</div>
            <div class="device-status">
              <n-tag :type="device.status == DeviceStatus.ONLINE ? 'success' : 'error'" size="small">
                {{ device.status == DeviceStatus.ONLINE ? '在线' : '离线' }}
              </n-tag>
            </div>
          </div>
          <div class="device-meta">
            <div class="device-os">{{ device.os }}</div>
            <div class="device-last-seen" v-if="device.status == DeviceStatus.OFFLINE">
              最后在线: {{ formatLastSeen(device.lastSeen) }}
            </div>
          </div>
        </n-card>
      </div>
    </n-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h, nextTick } from 'vue';

import { useRouter } from 'vue-router';
import { Device, DeviceStatus } from '@/types/device'
import { useDeviceStore } from '@/stores/devices';
import { NSpin, NEmpty, NButton, NCard, NIcon, NTag } from 'naive-ui';
import { DesktopOutline, Refresh, LogoWindows, LogoApple } from '@vicons/ionicons5';

const router = useRouter();
const deviceStore = useDeviceStore();

const getDeviceIcon = (os: string) => {
  if (os.toLowerCase().includes('windows')) {
    return LogoWindows;
  } else if (os.toLowerCase().includes('mac')) {
    return LogoApple;
  }
  return DesktopOutline;
};

const formatLastSeen = (timestamp: number): string => {
  const now = new Date();
  const lastSeen = new Date(timestamp);
  const diffMs = now.getTime() - lastSeen.getTime();
  const diffMins = Math.round(diffMs / 60000);

  if (diffMins < 60) {
    return `${diffMins} 分钟前`;
  } else if (diffMins < 1440) {
    return `${Math.floor(diffMins / 60)} 小时前`;
  } else {
    return `${Math.floor(diffMins / 1440)} 天前`;
  }
};

const refreshDevices = async () => {
  try {
    await deviceStore.fetchDevices();
  } catch (error) {
    console.error('Failed to fetch devices:', error);
  }
};

const connectToDevice = (device: Device) => {
  if (device.status == DeviceStatus.ONLINE) {
    // router.push({
    //   name: 'remote-control',
    //   params: { deviceId: device.id }
    // });

    window.electronAPI.ipcRendererSend('require-open-control-window', device.id)
  }
};

onMounted(async () => {
  // load devices
  await refreshDevices();
});
</script>

<style scoped>
.devices-container {
  min-height: 400px;
}

.devices-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 24px;
  padding: 16px 0px;
}

.device-card {
  cursor: pointer;
  transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
}

.device-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.device-icon {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100px;
  background-color: #f5f5f5;
}

.device-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.device-name {
  font-weight: bold;
  overflow: hidden;
  text-overflow: ellipsis;
}

.device-meta {
  font-size: 12px;
  color: #999;
}

.device-os {
  margin-bottom: 4px;
}
</style>