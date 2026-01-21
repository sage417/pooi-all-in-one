<template>
  <div class="about-container">
    <div class="about-header">
      <n-space vertical align="center" justify="center">
        <div class="logo">
          <!-- <img src="../assets/logo.png" alt="Logo" /> -->
          <n-icon :component="DesktopOutline" size="64" />
        </div>
        <h1 class="app-name">PooiDesk</h1>
        <p class="app-version">版本 1.0.0</p>
      </n-space>
    </div>
    
    <n-card class="about-card" title="应用信息">
      <n-space vertical>
        <div class="info-item">
          <div class="info-label">当前版本</div>
          <div class="info-value">1.0.0</div>
        </div>
        <div class="info-item">
          <div class="info-label">操作系统</div>
          <div class="info-value">{{ systemInfo.os }}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Electron版本</div>
          <div class="info-value">{{ systemInfo.electronVersion }}</div>
        </div>
        <div class="info-item">
          <div class="info-label">设备ID</div>
          <div class="info-value">{{ systemInfo.deviceId }}</div>
        </div>
      </n-space>
    </n-card>
    
    <n-card class="about-card" title="使用说明">
      <p>
        PooiDesk是一款基于WebRTC的远程控制软件，可以帮助您在不同设备间实现远程操作和屏幕共享。
      </p>
      <p>
        您可以通过相同账号登录不同设备，并通过设备列表页面远程控制您的其他设备。
      </p>
      
      <h3>主要功能</h3>
      <ul>
        <li>屏幕实时共享</li>
        <li>远程键盘和鼠标控制</li>
        <li>跨平台支持（Windows、macOS）</li>
        <li>安全的端到端加密连接</li>
        <li>灵活的设置选项</li>
      </ul>
    </n-card>
    
    <n-card class="about-card" title="联系我们">
      <n-space vertical>
        <p>
          如果您有任何问题或建议，请通过以下方式联系我们：
        </p>
        <div class="contact-item">
          <n-icon :component="MailOutline" />
          <a href="mailto:support@example.com">support@example.com</a>
        </div>
        <div class="contact-item">
          <n-icon :component="GlobeOutline" />
          <a href="https://example.com" target="_blank">https://example.com</a>
        </div>
      </n-space>
    </n-card>
    
    <div class="footer">
      <p>&copy; 2025 PooiDesk. 保留所有权利。</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useDeviceStore } from '@/stores/devices';
import { 
  NSpace, 
  NCard, 
  NIcon,
} from 'naive-ui';
import { 
  DesktopOutline, 
  MailOutline, 
  GlobeOutline 
} from '@vicons/ionicons5';

const deviceStore = useDeviceStore();

const systemInfo = ref({
  os: '',
  electronVersion: '',
  deviceId: ''
});

onMounted(async () => {
  systemInfo.value = {
    os: deviceStore.getOperatingSystem(),
    electronVersion: window.navigator.userAgent.match(/Electron\/(\d+\.\d+\.\d+)/)?.[1] || '未知',
    deviceId: deviceStore.getCurrentDeviceId
  };
});
</script>

<style scoped>
.about-container {
  max-width: 800px;
  margin: 0 auto;
  padding-bottom: 40px;
}

.about-header {
  text-align: center;
  margin-bottom: 32px;
}

.logo {
  margin-bottom: 16px;
}

.app-name {
  margin: 8px 0;
  font-size: 24px;
  font-weight: bold;
}

.app-version {
  margin: 0;
  color: #666;
}

.about-card {
  margin-bottom: 24px;
}

.info-item {
  display: flex;
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}

.info-item:last-child {
  border-bottom: none;
}

.info-label {
  width: 120px;
  color: #666;
}

.contact-item {
  display: flex;
  align-items: center;
  margin: 8px 0;
}

.contact-item a {
  margin-left: 8px;
  color: #2080f0;
  text-decoration: none;
}

.contact-item a:hover {
  text-decoration: underline;
}

.footer {
  text-align: center;
  margin-top: 32px;
  color: #999;
  font-size: 14px;
}

ul {
  padding-left: 20px;
}

h3 {
  margin-top: 16px;
  margin-bottom: 8px;
}
</style>