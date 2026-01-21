// 远程控制相关的类型定义

export interface RemoteConnectionInfo {
    deviceId: string;
    deviceName: string;
    os: string;
    resolution: string;
  }
  
  // 远程设备信息
  export interface RemoteDevice {
    id: string;
    name: string;
    os: string;
    osVersion?: string;
    ip?: string;
    lastSeen: Date;
    online: boolean;
    status: 'idle' | 'busy' | 'offline';
  }
  
  // 远程控制设置
  export interface RemoteControlSettings {
    quality: 'low' | 'medium' | 'high' | 'ultra';
    frameRate: number;
    enableAudio: boolean;
    enableClipboard: boolean;
    controlMode: 'askEveryTime' | 'alwaysAllow' | 'neverAllow';
  }
  
  // 控制会话信息
  export interface ControlSession {
    id: string;
    controllerDeviceId: string;
    controllerName: string;
    targetDeviceId: string;
    targetName: string;
    startTime: Date;
    duration: number;
    active: boolean;
  }
  
  // WebRTC ICE服务器配置
  export interface IceServer {
    urls: string | string[];
    username?: string;
    credential?: string;
  }