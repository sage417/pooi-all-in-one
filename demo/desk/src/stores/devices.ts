import {defineStore} from 'pinia';
import {useKeycloak} from '@dsb-norge/vue-keycloak-js';
import {Device, DeviceStatus} from '../types/device'

export const useDeviceStore = defineStore('device', {
  state: () => ({
    currentDeviceId: '' as string,
    devices: [] as Device[],
    loading: false,
    error: null as string | null,
  }),

  getters: {
    getDevices: (state): Device[] => state.devices,
    isLoading: (state) => state.loading,
    getDeviceById: (state) => (id: string) => {
      return state.devices.find(device => device.id === id) || null;
    },
    getCurrentDeviceId: (state) => state.currentDeviceId
  },

  actions: {
    async registerDevice() {
      const keycloak = useKeycloak();
      if (!keycloak.authenticated) {
        return []
      }

      this.loading = true;

      try {
        // 获取设备信息
        const deviceInfo = {
          name: this.getDeviceName(),
          os: this.getOperatingSystem(),
          online: true,
          lastSeen: Date.now(),
        };

        // 发送到服务器注册设备
        const response = await fetch('https://api.yourdomain.com/devices/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${keycloak.token}`
          },
          body: JSON.stringify(deviceInfo)
        });

        if (!response.ok) {
          throw new Error('Failed to register device');
        }

        const data = await response.json();
        this.currentDevice = data;

        return data;
      } catch (error) {
        this.error = error.message;
        throw error;
      } finally {
        this.loading = false;
      }
    },
    async fetchDevices() {
      const keycloak = useKeycloak();
      if (!keycloak.authenticated) {
        return []
      }

      this.loading = true;

      try {
        // 为了演示，这里使用模拟数据
        // 实际应用中，应该从服务器获取设备列表
        // const response = await fetch('https://api.yourdomain.com/devices', {
        //   headers: {
        //     'Authorization': `Bearer ${keycloak.token}`
        //   }
        // });

        // if (!response.ok) {
        //   throw new Error('Failed to fetch devices');
        // }

        // const data = await response.json();
        // this.devices = data;

        // 模拟数据
        await new Promise(resolve => setTimeout(resolve, 100));

        this.devices = [
          {
            id: 'd08581b1bf93104552d632efd7ca807f1fd5fb5838a6f4884e2a008a0464839e',
            name: 'DESKTOP-SLPBF20',
            os: 'Windows 10',
            address: "192.168.2.122",
            status: DeviceStatus.ONLINE,
            lastSeen: Date.now(),
            userId: keycloak.userName
          },
          {
            id: '5f1fbab8dd9c11a6e3986dfb15262fbe0d461eb5fced3412ffa0df1030754d80',
            name: 'DESKTOP-2HSQ8FP',
            os: 'Windows 10',
            address: "192.168.2.105",
            status: DeviceStatus.ONLINE,
            lastSeen: Date.now(),
            userId: keycloak.userName
          },
          {
            id: '3',
            name: 'MacBook Pro',
            os: 'macOS Ventura',
            status: DeviceStatus.OFFLINE,
            lastSeen: Date.now() - 3600000 * 3, // 3小时前
            userId: keycloak.userName
          }
        ].filter(device => device.id !== this.currentDeviceId);

        return this.devices;
      } catch (error) {
        this.error = error.message;
        throw error;
      } finally {
        this.loading = false;
      }
    },
    getOperatingSystem() {
      const userAgent = window.navigator.userAgent;
      const platform = window.navigator.platform;

      if (/Mac/.test(platform)) return 'macOS';
      if (/Win/.test(platform)) return 'Windows';
      if (/Linux/.test(platform)) return 'Linux';

      if (/Mac/.test(userAgent)) return 'macOS';
      if (/Windows/.test(userAgent)) return 'Windows';
      if (/Linux/.test(userAgent)) return 'Linux';

      return navigator.platform || 'Unknown OS';
    },
    setDeviceId(deviceId: string) {
      this.currentDeviceId = deviceId
    }
  }
});