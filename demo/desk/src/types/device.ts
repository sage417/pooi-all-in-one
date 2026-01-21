// src/types/device.ts

/**
 * 设备类型枚举
 */
export enum DeviceType {
    WINDOWS = 'windows',
    MAC = 'mac',
    LINUX = 'linux',
    UNKNOWN = 'unknown'
}

/**
 * 设备状态枚举
 */
export enum DeviceStatus {
    ONLINE = 'online',
    OFFLINE = 'offline',
    BUSY = 'busy' // 设备正在被控制或者正在控制其他设备
}

/**
 * 设备信息接口
 */
export interface Device {
    id: string;
    name: string;
    os: string;
    address: string;
    status: DeviceStatus;
    lastSeen: number;
    userId: string;
}

/**
 * 设备连接信息接口
 */
export interface DeviceConnection {
    deviceId: string;           // 设备ID
    connectionId: string;       // 连接ID
    startTime: Date;            // 连接开始时间
    isController: boolean;      // 是否为控制方
    isControlled: boolean;      // 是否被控制
    peerId?: string;            // 对方设备ID
    peerName?: string;          // 对方设备名称
    status: ConnectionStatus;   // 连接状态
}

/**
 * 连接状态枚举
 */
export enum ConnectionStatus {
    CONNECTING = 'connecting',
    CONNECTED = 'connected',
    DISCONNECTED = 'disconnected',
    FAILED = 'failed'
}

/**
 * 设备发现请求接口
 */
export interface DeviceDiscoveryRequest {
    userId: string;       // 用户ID
    deviceId: string;     // 设备ID
    timestamp: number;    // 时间戳
}

/**
 * 设备发现响应接口
 */
export interface DeviceDiscoveryResponse {
    deviceId: string;         // 设备ID
    name: string;             // 设备名称
    type: DeviceType;         // 设备类型
    status: DeviceStatus;     // 设备状态
    timestamp: number;        // 时间戳
}

/**
 * 控制请求接口
 */
export interface ControlRequest {
    controllerDeviceId: string;  // 控制方设备ID
    targetDeviceId: string;      // 目标设备ID
    timestamp: number;           // 时间戳
    sessionId?: string;          // 会话ID，可选
}

/**
 * 控制响应接口
 */
export interface ControlResponse {
    accepted: boolean;           // 是否接受控制请求
    targetDeviceId: string;      // 目标设备ID
    controllerDeviceId: string;  // 控制方设备ID
    timestamp: number;           // 时间戳
    sessionId?: string;          // 会话ID，可选
    reason?: string;             // 拒绝原因，可选
}

/**
 * 设备系统信息接口
 */
export interface DeviceSystemInfo {
    osName: string;          // 操作系统名称
    osVersion: string;       // 操作系统版本
    cpuModel: string;        // CPU型号
    cpuCores: number;        // CPU核心数
    totalMemory: number;     // 总内存(MB)
    freeMemory: number;      // 可用内存(MB)
    screenResolution: {      // 屏幕分辨率
        width: number;
        height: number;
    };
    hostname: string;        // 主机名
    username: string;        // 用户名
}