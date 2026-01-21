// See the Electron documentation for details on how to use preload scripts:
// https://www.electronjs.org/docs/latest/tutorial/process-model#preload-scripts
import {contextBridge, ipcRenderer, IpcRendererEvent} from 'electron';

// 定义暴露给渲染进程的 API 类型
interface ElectronAPI {
    ipcRendererInvoke: (channel: string, ...args: any[]) => Promise<any>;
    ipcRendererSend: (channel: string, ...args: any[]) => void;
    ipcRendererOn: (channel: string, listener: (event: IpcRendererEvent, ...args: any[]) => void) => void;
}

// 安全地暴露 IPC 方法到渲染进程
contextBridge.exposeInMainWorld('electronAPI', {
    ipcRendererInvoke: (channel: string, ...args: any[]) => {
        return ipcRenderer.invoke(channel, ...args);
    },
    ipcRendererSend: (channel: string, ...args: any[]) => {
        ipcRenderer.send(channel, ...args)
    },
    ipcRendererOn: (channel: string, listener: (event: IpcRendererEvent, ...args: any[]) => void) => {
        ipcRenderer.on(channel, listener);
    }
} as ElectronAPI);

declare global {
    interface Window {
        electronAPI: ElectronAPI;
    }
}