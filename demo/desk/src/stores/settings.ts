import {defineStore} from 'pinia';

interface Settings {
  deviceName?: string;
  theme: 'light' | 'dark' | 'system';
  startOnBoot: boolean;
  requireConfirmation: boolean;
  streamQuality: 'low' | 'medium' | 'high';
  useAccessCode: boolean;
  accessCode: number;
  idleLockTime: number;
}

const DEFAULT_SETTINGS: Settings = {
  theme: 'light',
  startOnBoot: false,
  requireConfirmation: true,
  streamQuality: 'medium',
  useAccessCode: false,
  accessCode: 1234,
  idleLockTime: 10
};

export const useSettingsStore = defineStore('settings', {
  state: () => ({
    settings: { ...DEFAULT_SETTINGS } as Settings,
    isLoading: false,
    error: null as string | null,
  }),
  
  getters: {
    getSettings: (state) => state.settings,
    getTheme: (state) => state.settings.theme,
    getStreamQuality: (state) => state.settings.streamQuality,
  },
  
  actions: {
    async loadSettings() {
      this.isLoading = true;
      
      try {
        // 从localStorage加载设置
        const savedSettings = localStorage.getItem('appSettings');
        
        if (savedSettings) {
          this.settings = JSON.parse(savedSettings);
        } else {
          // 如果没有保存的设置，使用默认设置
          this.settings = { ...DEFAULT_SETTINGS };
        }
      } catch (error) {
        this.error = error.message;
        this.settings = { ...DEFAULT_SETTINGS };
      } finally {
        this.isLoading = false;
      }
    },
    
    async saveSettings(newSettings: Settings) {
      this.isLoading = true;
      
      try {
        // 保存设置到localStorage
        localStorage.setItem('appSettings', JSON.stringify(newSettings));
        
        // 更新状态
        this.settings = { ...newSettings };
        
        // 应用设置
        this.applySettings();
        
        return true;
      } catch (error) {
        this.error = error.message;
        throw error;
      } finally {
        this.isLoading = false;
      }
    },
    
    resetSettings() {
      // 重置为默认设置
      this.settings = { ...DEFAULT_SETTINGS };
      localStorage.removeItem('appSettings');
      this.applySettings();
    },
    
    applySettings() {
      // 应用主题
      document.documentElement.setAttribute('data-theme', this.settings.theme);
      
      // 应用开机自启设置 (Electron特定功能)
      if (window.electron) {
        window.electron.setAutoLaunch(this.settings.startOnBoot);
      }
      
      // 其他设置应用逻辑...
    }
  }
});