<template>
  <n-layout has-sider>
    <n-layout-sider bordered :width="200">
      <div class="logo">
        <!-- <img src="../assets/logo.png" alt="Logo" /> -->
        <span>PooiDesk</span>
      </div>
      <n-menu :options="menuOptions" :default-value="menuOptions[0].key" @update:value="handleMenuUpdate" />
    </n-layout-sider>
    <n-layout>
      <n-layout-header bordered>
        <div class="header-content">
          <div class="header-title">{{ pageTitle }}</div>
          <div class="user-info">
            <span>{{ $keycloak.userName }}</span>
            <n-button @click="$keycloak.logoutFn" text>退出</n-button>
          </div>
        </div>
      </n-layout-header>
      <n-layout-content content-style="padding: 24px;">
        <router-view />
      </n-layout-content>
    </n-layout>
  </n-layout>
</template>

<script setup lang="ts">
import { ref, computed, Component, h } from 'vue';
import { useRouter, useRoute, RouterLink } from 'vue-router';

import { NLayout, NLayoutSider, NLayoutHeader, NLayoutContent, NMenu, NButton, NIcon, MenuOption } from 'naive-ui';
import { DesktopOutline, SettingsOutline, InformationCircleOutline } from '@vicons/ionicons5';
// import { renderIcon } from '@/utils/icons';


const route = useRoute();

function renderIcon(icon: Component) {
  return () => h(NIcon, null, { default: () => h(icon) })
}

const pageTitle = computed(() => {
  switch (route.name) {
    case 'devices': return '设备';
    case 'settings': return '设置';
    case 'about': return '关于';
    default: return '设备';
  }
});

const router = useRouter();
const handleMenuUpdate = (key: string) => {
  router.push({ name: key });
};

const menuOptions: MenuOption[] = [
  {
    label: () =>
      h(
        RouterLink,
        {
          to: {
            name: 'devices',
            params: {}
          }
        },
        { default: () => '设备' }
      ),
    key: 'devices',
    icon: renderIcon(DesktopOutline)
  },
  {
    label: () =>
      h(
        RouterLink,
        {
          to: {
            name: 'settings',
            params: {}
          }
        },
        { default: () => '设置' }
      ),
    key: 'settings',
    icon: renderIcon(SettingsOutline)
  },
  {
    label: () =>
      h(
        RouterLink,
        {
          to: {
            name: 'about',
            params: {}
          }
        },
        { default: () => '关于' }
      ),
    key: 'about',
    icon: renderIcon(InformationCircleOutline)
  }
];


</script>

<style scoped>
.logo {
  display: flex;
  align-items: center;
  padding: 18px;
  gap: 8px;
}

.logo img {
  height: 32px;
  width: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 24px;
  height: 64px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 12px;
}
</style>