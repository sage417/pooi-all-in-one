// src/router/index.ts
import {createRouter, createWebHashHistory, RouteRecordRaw} from 'vue-router'
import Home from '../views/home.vue';
import Devices from '../views/devices.vue';
import Settings from '../views/settings.vue';
import About from '../views/about.vue';
import RemoteControl from '../views/remoteControl.vue';
import {VueKeycloakInstance} from '@dsb-norge/vue-keycloak-js';

const routes: Readonly<RouteRecordRaw[]> = [
  {
    path: '/',
    component: Home,
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'devices',
        component: Devices,
      },
      {
        path: 'settings',
        name: 'settings',
        component: Settings,
      },
      {
        path: 'about',
        name: 'about',
        component: About,
      },
    ],
  },
  {
    path: '/remote-control/:deviceId',
    name: 'remote-control',
    component: RemoteControl,
    meta: { requiresAuth: true },
  },
];

export const initializeRouter = (keycloak: VueKeycloakInstance) => {
  const router = createRouter({
    history: createWebHashHistory(),
    routes,
  })

  router.beforeEach(async (to, from) => {
    // 检查 hash 部分是否包含 Keycloak 参数
    if (to.path.includes("&state=") && to.path.includes("&code=")) {
      // 如果是从 Keycloak 重定向回来的
      // 清理 URL，保留基本路径
      return { path: to.path.substring(0, to.path.indexOf("&state=")), replace: true };
    }

    // 检查是否需要认证的路由
    if (to.matched.some(record => record.meta.requiresAuth)) {
      if (keycloak.authenticated) {
        return true; // 继续导航
      } else {
        // await keycloak.login()
        return true; // 中止当前导航
      }
    }

    return true; // 对于不需要认证的路由，直接通过
  });

  return router
}