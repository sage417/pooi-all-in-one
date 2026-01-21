<template>
  <div class="remote-control-container">
    <div class="connection-status" :class="{ connected: isConnected }">
      {{ connectionStatusText }}
    </div>

    <div class="remote-screen-container" v-show="isConnected">
      <video ref="remoteVideo" class="remote-screen" autoplay></video>

      <div class="control-panel">
        <n-button-group>
          <n-button @click="toggleFullscreen" size="small">
            <template #icon>
              <n-icon>
                <ExpandOutline v-if="!isFullscreen" />
                <ContractOutline v-else />
              </n-icon>
            </template>
            {{ isFullscreen ? '退出全屏' : '全屏' }}
          </n-button>

          <n-button @click="sendCtrlAltDel" size="small">
            <template #icon>
              <n-icon>
                <RefreshOutline />
              </n-icon>
            </template>
            Ctrl+Alt+Del
          </n-button>

          <n-button @click="disconnectSession" type="error" size="small">
            <template #icon>
              <n-icon>
                <ExitOutline />
              </n-icon>
            </template>
            断开连接
          </n-button>
        </n-button-group>
      </div>

      <div class="connection-info" v-if="connectionInfo">
        <n-space vertical>
          <div>设备名称: {{ connectionInfo.deviceName }}</div>
          <div>操作系统: {{ connectionInfo.os }}</div>
          <div>分辨率: {{ connectionInfo.resolution }}</div>
          <div>连接时间: {{ formatConnectTime }}</div>
        </n-space>
      </div>
    </div>

    <div class="connection-screen" v-if="!isConnected && !isConnecting">
      <n-result status="info" title="未连接" description="等待建立与远程设备的连接">
        <template #footer>
          <n-button @click="initConnection" type="primary">重新连接</n-button>
        </template>
      </n-result>
    </div>

    <div class="connecting-screen" v-if="isConnecting">
      <n-spin size="large" />
      <div class="connecting-text">正在连接远程设备...</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { NSpin, NButtonGroup, NButton, NCard, NIcon, NSpace, NResult, useMessage } from 'naive-ui';
import { WebRTCService } from '../services/webrtc';
import { useDeviceStore } from '../stores/devices';
import { ExpandOutline, ContractOutline, HandRightOutline, RefreshOutline, ExitOutline } from '@vicons/ionicons5';
import type { RemoteConnectionInfo } from '../types';
import { DeviceStatus } from '../types/device';

const route = useRoute();
const router = useRouter();
const message = useMessage();
const deviceStore = useDeviceStore();

// 状态变量
const isConnected = ref(false);
const isConnecting = ref(false);
const isFullscreen = ref(false);
const remoteVideo = ref<HTMLVideoElement | null>(null);
const webrtcService = ref<WebRTCService | null>(null);
const connectionInfo = ref<RemoteConnectionInfo | null>(null);

const connectTime = ref<Date | null>(null);

// 计算属性
const deviceId = computed(() => route.params.deviceId as string);

const connectionStatusText = computed(() => {
  if (isConnected.value) {
    return '已连接';
  } else if (isConnecting.value) {
    return '正在连接...';
  } else {
    return '未连接';
  }
});

const formatConnectTime = computed(() => {
  if (!connectTime.value) return '';
  return connectTime.value.toLocaleString();
});

// 方法
const initConnection = async () => {
  try {
    isConnecting.value = true;

    // 检查设备是否在线
    const device = deviceStore.getDeviceById(deviceId.value);

    if (!device) {
      throw new Error(`设备不存在 deviceId: ${deviceId.value}`);
    }

    // if (device.status == DeviceStatus.OFFLINE) {
    //   throw new Error('设备不在线');
    // }

    // 创建WebRTC服务实例
    webrtcService.value = new WebRTCService({
      deviceId: deviceId.value,
      onConnect: handleConnect,
      onDisconnect: handleDisconnect,
      onError: handleError,
      onRemoteStream: handleRemoteStream
    });

    // 初始化连接
    await webrtcService.value.connect();
  } catch (error) {
    handleError(error instanceof Error ? error : new Error('连接失败'));
  }
};

const handleConnect = (info: RemoteConnectionInfo) => {
  isConnected.value = true;
  isConnecting.value = false;
  connectionInfo.value = info;
  connectTime.value = new Date();
  message.success('已成功连接到远程设备');
};

const handleDisconnect = () => {
  isConnected.value = false;

  isConnecting.value = false;
  connectionInfo.value = null;
  message.info('已断开与远程设备的连接');
};

const handleError = (error: Error) => {
  isConnected.value = false;
  isConnecting.value = false;
  message.error(`连接错误: ${error.message}`);
};

const handleRemoteStream = (stream: MediaStream) => {
  if (remoteVideo.value) {
    remoteVideo.value.srcObject = stream;
    remoteVideo.value.onloadedmetadata = (_) => remoteVideo.value.play()
    console.log('handleRemoteStream')
  }
};

const toggleControl = () => {
  if (!webrtcService.value || !isConnected.value) return;

  webrtcService.value.enableControl();
  // message.success('已启用远程控制');
};

const toggleFullscreen = () => {
  if (!remoteVideo.value) return;

  if (!document.fullscreenElement) {
    remoteVideo.value.requestFullscreen().then(() => {
      isFullscreen.value = true;
    }).catch(err => {
      message.error(`全屏错误: ${err.message}`);
    });
  } else {
    document.exitFullscreen().then(() => {
      isFullscreen.value = false;
    }).catch(err => {
      message.error(`退出全屏错误: ${err.message}`);
    });
  }
};

const sendCtrlAltDel = () => {
  if (!webrtcService.value || !isConnected.value) return;
  webrtcService.value.sendSpecialKeys('ctrl+alt+delete');
  message.info('已发送 Ctrl+Alt+Del 命令');
};

const disconnectSession = () => {
  if (webrtcService.value) {
    webrtcService.value.disconnect();
  }
  router.push({ name: 'devices' });
};

// 键盘和鼠标事件处理
const handleKeyDown = (event: KeyboardEvent) => {
  // prevent control window event
  event.preventDefault();
  if (!webrtcService.value || !isConnected.value) return;
  webrtcService.value.sendKeyEvent('keydown', event);
};

const handleKeyUp = (event: KeyboardEvent) => {
  // prevent control window event
  event.preventDefault();
  if (!webrtcService.value || !isConnected.value) return;
  webrtcService.value.sendKeyEvent('keyup', event);
};

const handleMouseMove = (event: MouseEvent) => {
  if (!webrtcService.value || !isConnected.value) return;

  const videoRect = remoteVideo.value.getBoundingClientRect();
  const x = (event.clientX - videoRect.left) / videoRect.width;
  const y = (event.clientY - videoRect.top) / videoRect.height;
  console.log(event)
  webrtcService.value.sendMouseMove(x, y);
};

const handleMouseDown = (event: MouseEvent) => {
  if (!webrtcService.value || !isConnected.value) return;
  webrtcService.value.sendMouseEvent('mousedown', event);
};

const handleMouseUp = (event: MouseEvent) => {
  if (!webrtcService.value || !isConnected.value) return;
  webrtcService.value.sendMouseEvent('mouseup', event);
};

const handleWheel = (event: WheelEvent) => {
  if (!webrtcService.value || !isConnected.value) return;
  webrtcService.value.sendWheelEvent(event);
};

// 生命周期钩子
onMounted(async () => {
  // new window fetch devices
  await deviceStore.fetchDevices()

  // // 自动连接
  initConnection();

  isConnected.value = true

  // navigator.mediaDevices.getDisplayMedia({
  //   audio: false,
  //   video: {
  //     width: 1980,
  //     height: 1080,
  //     frameRate: 30
  //   }
  // }).then(stream => {
  //   remoteVideo.value.srcObject = stream
  //   remoteVideo.value.onloadedmetadata = (_) => remoteVideo.value.play()
  // }).catch(e => console.log(e))

  document.addEventListener('keydown', handleKeyDown);
  document.addEventListener('keyup', handleKeyUp);

  if (remoteVideo.value) {
    remoteVideo.value.addEventListener('mousemove', handleMouseMove);
    // remoteVideo.value.addEventListener('mousedown', handleMouseDown);
    // remoteVideo.value.addEventListener('mouseup', handleMouseUp);
    // remoteVideo.value.addEventListener('wheel', handleWheel);
  }

  // 检测全屏状态变化
  document.addEventListener('fullscreenchange', () => {
    isFullscreen.value = !!document.fullscreenElement;
  });
});

onUnmounted(() => {
  document.removeEventListener('keydown', handleKeyDown);
  document.removeEventListener('keyup', handleKeyUp);
  document.removeEventListener('fullscreenchange', () => { });

  if (remoteVideo.value) {
    remoteVideo.value.removeEventListener('mousemove', handleMouseMove);
    remoteVideo.value.removeEventListener('mousedown', handleMouseDown);
    remoteVideo.value.removeEventListener('mouseup', handleMouseUp);
    remoteVideo.value.removeEventListener('wheel', handleWheel);
  }

  if (webrtcService.value) {
    webrtcService.value.disconnect();
  }
});
</script>

<style scoped>
.remote-control-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
  position: relative;
}

.connection-status {
  position: absolute;
  top: 10px;
  right: 10px;
  padding: 5px 10px;
  border-radius: 4px;
  background-color: rgba(255, 0, 0, 0.7);
  color: white;
  font-weight: bold;
  z-index: 10;
}

.connection-status.connected {
  background-color: rgba(0, 128, 0, 0.7);
}

.remote-screen-container {
  flex: 1;
  position: relative;
  background-color: #333;
  overflow: hidden;
}

.remote-screen {
  width: 100%;
  height: 100%;
  object-fit: contain;
  background-color: #000;
}

.control-panel {
  position: absolute;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%);
  background-color: rgba(0, 0, 0, 0.7);
  padding: 10px;
  border-radius: 8px;
  z-index: 100;
  transition: opacity 0.3s;
  opacity: 0.3;
}

.control-panel:hover {
  opacity: 1;
}

.connection-info {
  position: absolute;
  top: 10px;
  left: 10px;
  background-color: rgba(0, 0, 0, 0.7);
  color: white;
  padding: 10px;
  border-radius: 8px;
  font-size: 12px;
  z-index: 100;
  transition: opacity 0.3s;
  opacity: 0.3;
}

.connection-info:hover {
  opacity: 1;
}

.connection-screen,
.connecting-screen {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  width: 100%;
}

.connecting-text {
  margin-top: 20px;
  font-size: 16px;
  color: #333;
}
</style>