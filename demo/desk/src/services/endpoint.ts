// src/services/webrtc/endpoint.ts
import {useDeviceStore} from '@/stores/devices'
import {useSignalStore} from '@/stores/signal'
import {SignalMessage, SignalServer} from '@/services/signalService'
import {ChannelType} from '@/types/datachannel'


export class ControlledEndpoint {
    private peerConnection: RTCPeerConnection | null = null
    private dataChannel: RTCDataChannel | null = null
    private screenStream: MediaStream | null = null
    private deviceStore = useDeviceStore()
    private signalStore = useSignalStore()
    // private isConnected = false
    private isScreenSharing = false
    private isControlEnabled = false
    private remoteDeviceId = ''
    private signalServer: SignalServer | null = null
    private candidateCache: SignalMessage[] = []

    constructor() {
        this.signalServer = this.signalStore.signalServer as SignalServer
    }

    async start() {
        await this.initpeerConnection()

        this.signalServer.onOffer(message => this.handleOffer(message))
        this.signalServer.onIceCandidate(message => this.handleIceCandidate(message))
        this.signalServer.start()
    }

    close() {
        this.signalServer.close()
    }

    private async initpeerConnection(): Promise<void> {
        if (this.peerConnection) {
            this.peerConnection.close()
        }
        const configuration: RTCConfiguration = {
            iceServers: []
        }

        this.peerConnection = new RTCPeerConnection(configuration)

        this.peerConnection.onicecandidate = (event) => {

            if (event.candidate) {
                if (!this.signalServer || this.signalServer.readyState() !== WebSocket.OPEN) {
                    return
                }

                const webrtcCandidate: SignalMessage = {
                    type: 'webrtc:ice-candidate',
                    targetDeviceId: this.remoteDeviceId,
                    deviceId: this.deviceStore.currentDeviceId,
                    fromDeviceId: this.deviceStore.currentDeviceId,
                    sdp: event.candidate
                }
                this.signalServer.send(webrtcCandidate)
            }
        }

        this.peerConnection.ondatachannel = (event) => {
            this.dataChannel = event.channel
            this.setupDataChannel()
        }
    }

    private async handleOffer(message: SignalMessage): Promise<void> {
        try {
            if (!this.peerConnection) {
                this.initpeerConnection()
            }
            // set remote desc before create answer
            await this.peerConnection.setRemoteDescription(new RTCSessionDescription(message.sdp))
            console.log('remote set')
            // record control deviceid
            this.remoteDeviceId = message.fromDeviceId;

            // add track before create answer or negotiation then
            await this.startScreenSharing()

            // must set remote desc before create answer
            const answer = await this.peerConnection.createAnswer()
            await this.peerConnection.setLocalDescription(answer)

            const webrtcAnswer: SignalMessage = {
                type: 'webrtc:answer',
                targetDeviceId: this.remoteDeviceId,
                deviceId: this.deviceStore.currentDeviceId,
                fromDeviceId: this.deviceStore.currentDeviceId,
                sdp: answer
            }

            this.signalServer.send(webrtcAnswer)
        } catch (error) {
            console.error('Error handling offer:', error)
        }
    }

    // 处理ICE候选
    private async handleIceCandidate(message: SignalMessage): Promise<void> {
        if (!this.peerConnection) {
            return
        }
        this.candidateCache.push(message)
        if (this.peerConnection.remoteDescription?.type) {
            try {
                this.candidateCache.forEach(async m => {
                    await this.peerConnection.addIceCandidate(new RTCIceCandidate(m.sdp))
                    console.log('add candidate:', m.sdp)
                })
                this.candidateCache = []
            } catch (error) {
                console.error('Error adding ICE candidate:', error)
            }
        } else {
            console.warn('peerConnection remote not ready!')
        }
    }

    // 处理断开连接
    private handleDisconnect(): void {
        this.stopScreenSharing()
        this.closeConnection()
    }

    // 设置数据通道
    private setupDataChannel(): void {
        if (!this.dataChannel) return

        this.dataChannel.addEventListener('open', (event) => {
            console.log('data channel opend', event)
            // this.isConnected = true
        })

        this.dataChannel.addEventListener('close', (event) => {
            console.log('data channel closed', event)
            // this.isConnected = false
        })

        this.dataChannel.onmessage = (event) => {
            // console.log(event.data)
            this.handleDataChannelMessage(event.data)
        }
    }


    public async startScreenSharing(): Promise<boolean> {

        try {
            if (!this.peerConnection) {
                console.error('No active connection')
                return false
            }

            this.screenStream = await navigator.mediaDevices.getDisplayMedia({
                audio: false,
                video: {
                    width: { ideal: 1920, max: 2560 },
                    height: { ideal: 1080, max: 1440 },
                    frameRate: { ideal: 30, max: 60 }
                }
            })

            const videoTracks = this.screenStream.getVideoTracks();
            if (videoTracks.length === 0) {
                // release resources
                this.screenStream.getTracks().forEach(t => t.stop());
                return false;
            }
            videoTracks[0].addEventListener('ended', (event) => this.stopScreenSharing());

            // 将屏幕流添加到对等连接
            if (this.peerConnection) {
                const existingTracks = this.peerConnection.getSenders().map(s => s.track);

                this.screenStream.getTracks().forEach(track => {
                    if (!existingTracks.includes(track)) {
                        this.peerConnection.addTrack(track, this.screenStream!)
                    }
                })
            }

            this.isScreenSharing = true

            // 通知控制端已开始屏幕共享
            this.sendControlMessage({
                type: 'screen-sharing-started'
            })

            return true
        } catch (error) {
            console.error('Error starting screen share:', error)
            return false
        }
    }

    public stopScreenSharing(): void {
        console.log('stopScreenSharing')

        const senders = this.peerConnection?.getSenders()

        if (this.screenStream) {
            this.screenStream.getTracks().forEach(track => {
                track.stop(); // 停止所有轨道
                const sender = senders?.find(s => s.track === track);
                if (sender) this.peerConnection.removeTrack(sender); // 从连接中移除轨道
            });
            this.screenStream = null;
        }
        this.isScreenSharing = false;
        // 通知控制端已停止屏幕共享
        this.sendControlMessage({ type: 'screen-sharing-stopped' });
    }

    // 启用远程控制
    public enableControl(): void {
        this.isControlEnabled = true

        // 监听鼠标和键盘事件
        document.addEventListener('mousemove', this.handleMouseMove)
        document.addEventListener('mousedown', this.handleMouseDown)
        document.addEventListener('mouseup', this.handleMouseUp)
        document.addEventListener('wheel', this.handleWheel)
        document.addEventListener('keydown', this.handleKeyDown)
        document.addEventListener('keyup', this.handleKeyUp)

        // 通知控制端已启用控制
        this.sendControlMessage({
            type: 'control-enabled'
        })
    }

    // 禁用远程控制
    public disableControl(): void {
        this.isControlEnabled = false

        // 移除鼠标和键盘事件监听
        document.removeEventListener('mousemove', this.handleMouseMove)
        document.removeEventListener('mousedown', this.handleMouseDown)
        document.removeEventListener('mouseup', this.handleMouseUp)
        document.removeEventListener('wheel', this.handleWheel)
        document.removeEventListener('keydown', this.handleKeyDown)
        document.removeEventListener('keyup', this.handleKeyUp)

        // 通知控制端已禁用控制
        this.sendControlMessage({
            type: 'control-disabled'
        })
    }

    // 处理来自数据通道的消息
    private handleDataChannelMessage(data: ArrayBuffer): void {
        const messageView = new Uint8Array(data);
        const channelType = messageView[0]; // 第一个字节是通道类型
        const payload = data.slice(1); // 剩余部分是实际数据负载

        switch (channelType) {
            case ChannelType.Mouse:
                // handleMouseData(payload);
                break;
            case ChannelType.Keyboard:
                window.electronAPI.ipcRendererSend('simulate-keyevent', payload)
                break;
            case ChannelType.Clipboard:
                // handleClipboardData(payload);
                break;
            case ChannelType.Command:
                // handleCommandData(payload);
                break;
            default:
                console.error('Unknown channel type:', channelType);
        }
    }


    // 模拟鼠标移动
    private simulateMouseMove(x: number, y: number): void {
        // Electron环境中，通过robotjs或electron-robotjs模拟鼠标移动
        // 这里需要通过Electron的IPC与主进程通信
        window.electronAPI.ipcRendererSend('simulate-mouse-move', { x, y })
    }

    // 模拟鼠标按下
    private simulateMouseDown(button: string, x: number, y: number): void {
        window.electronAPI.ipcRendererSend('simulate-mouse-down', { button, x, y })
    }

    // 模拟鼠标释放
    private simulateMouseUp(button: string, x: number, y: number): void {
        window.electronAPI.ipcRendererSend('simulate-mouse-up', { button, x, y })
    }

    // 模拟滚轮事件
    private simulateWheel(deltaX: number, deltaY: number): void {
        window.electronAPI.ipcRendererSend('simulate-wheel', { deltaX, deltaY })
    }

    // 模拟键盘按下
    // private simulateKeyDown(key: string, code: string, modifiers: string[]): void {
    //     window.electronAPI.ipcRendererSend('simulate-key-down', { key, code, modifiers })
    // }

    // 模拟键盘释放
    // private simulateKeyUp(key: string, code: string): void {
    //     window.electronAPI.ipcRendererSend('simulate-key-up', { key, code })
    // }

    // 处理剪贴板数据
    private handleClipboardData(text: string): void {
        window.electronAPI.ipcRendererSend('set-clipboard', { text })
    }

    // 处理控制请求
    private handleControlRequest(): void {
        // 这里可以显示对话框让用户确认是否允许远程控制
        // 示例实现，实际应用中应该使用UI框架的对话框组件
        const allowControl = window.confirm('允许远程控制此设备吗？')

        if (allowControl) {
            this.enableControl()
        } else {
            this.sendControlMessage({
                type: 'control-rejected'
            })
        }
    }


    // 发送控制消息
    private sendControlMessage(data: any): void {
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            return
        }

        this.dataChannel.send(JSON.stringify(data))
    }

    // 关闭连接
    public closeConnection(): void {
        this.disableControl()
        this.stopScreenSharing()

        if (this.dataChannel) {
            this.dataChannel.close()
            this.dataChannel = null
        }

        if (this.peerConnection) {
            this.peerConnection.close()
            this.peerConnection = null
        }

        // this.isConnected = false
        this.remoteDeviceId = ''
    }

    // 获取连接状态
    public getConnectionState(): {
        isConnected: boolean,
        isScreenSharing: boolean,
        isControlEnabled: boolean,
        remoteDeviceId: string
    } {
        return {
            isConnected: true,
            isScreenSharing: this.isScreenSharing,
            isControlEnabled: this.isControlEnabled,
            remoteDeviceId: this.remoteDeviceId
        }
    }

    // 处理来自本地UI的鼠标事件（用于本地记录和处理）
    private handleMouseMove = (event: MouseEvent): void => {
        // 在这里可以添加本地处理逻辑
    }

    private handleMouseDown = (event: MouseEvent): void => {
        // 在这里可以添加本地处理逻辑
    }

    private handleMouseUp = (event: MouseEvent): void => {
        // 在这里可以添加本地处理逻辑
    }

    private handleWheel = (event: WheelEvent): void => {
        // 在这里可以添加本地处理逻辑
    }

    private handleKeyDown = (event: KeyboardEvent): void => {
        // 在这里可以添加本地处理逻辑
    }

    private handleKeyUp = (event: KeyboardEvent): void => {
        // 在这里可以添加本地处理逻辑
    }
}
