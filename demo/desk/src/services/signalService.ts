import {useDeviceStore} from '../stores/devices'
import {EventEmitter} from 'eventemitter3';

type SignalMessageType = 'webrtc:offer' | 'webrtc:answer' | 'webrtc:ice-candidate' | 'register' | 'unregister' | 'ping';

export interface SignalMessage {
    type: SignalMessageType;
    deviceId?: string;

    [key: string]: any;
}


export class SignalServer {

    private deviceStore = useDeviceStore()
    private eventEmitter = new EventEmitter()
    private signalServer: WebSocket | null = null
    private eventHandlers: { [key: string]: EventListener[] } = {};

    constructor(private signalServerUrl: string) {

    }

    async start() {
        await this.initSignalServer()
    }

    close() {
        this.eventEmitter.removeAllListeners()
        if (this.signalServer) {
            this.unregisterDevice()
            this.signalServer.close(1000)
        }
    }

    public onOffer(callback: (message: SignalMessage) => void) {
        this.eventEmitter.on('webrtc:offer', callback);
    }

    public onAnswer(callback: (message: SignalMessage) => void) {
        this.eventEmitter.on('webrtc:answer', callback);
    }

    public onIceCandidate(callback: (message: SignalMessage) => void) {
        this.eventEmitter.on('webrtc:ice-candidate', callback);
    }

    public readyState(): number {
        return this.signalServer.readyState
    }

    send(message: SignalMessage) {
        if (!this.isConnected()) {
            console.warn('[signalServer] Cannot send message: not connected');
            return
        }
        console.log('[signalServer] send:', JSON.stringify(message))
        this.signalServer.send(JSON.stringify(message))
    }

    private initSignalServer(): Promise<void> {
        return new Promise((resolve, reject) => {

            if (this.signalServer) {
                this.removeAllSocketEventListeners();
                this.signalServer.close();
            }

            try {
                this.signalServer = new WebSocket(this.signalServerUrl)

                this.addSocketEventListener('open', () => {
                    console.log('Signal server connected')
                    this.registerDevice()
                    resolve()
                })

                this.addSocketEventListener('message', (event) => {
                    console.log('[signalServer] receive:', event.data)
                    const message: SignalMessage = JSON.parse(event.data);
                    this.eventEmitter.emit(message.type, message)
                })

                this.addSocketEventListener('error', (event) => {
                    console.error('[signalServer] error:', event)
                })

                this.addSocketEventListener('close', (event) => {
                    console.log(`[signalServer] disconnected with code: ${event.code}`);
                    setTimeout(() => this.initSignalServer()
                        .catch(err => {
                            console.error('[signalServer] Reconnection failed:', err);
                        }), 5000
                    )
                })
            } catch (error) {
                console.error('Failed to init signal server:', error)
                reject(error)
            }
        })
    }

    private isConnected(): boolean {
        return this.signalServer !== null && this.signalServer.readyState === WebSocket.OPEN;
    }

    private addSocketEventListener<K extends keyof WebSocketEventMap>(type: K, listener: (this: WebSocket, ev: WebSocketEventMap[K]) => any) {

        if (!this.signalServer) return;

        this.signalServer.addEventListener(type, listener);

        if (!this.eventHandlers[type]) {
            this.eventHandlers[type] = [];
        }
        this.eventHandlers[type].push(listener);
    }

    private removeAllSocketEventListeners() {
        if (!this.signalServer) return;

        Object.entries(this.eventHandlers).forEach(([type, listeners]) => {
            listeners.forEach(listener => {
                this.signalServer?.removeEventListener(type, listener);
            });
        });

        this.eventHandlers = {};
    }

    private registerDevice(): void {
        if (!this.isConnected()) {
            return
        }
        this.signalServer.send(JSON.stringify({
            type: 'register',
            deviceId: this.deviceStore.currentDeviceId
        }))
    }

    private unregisterDevice(): void {
        if (!this.isConnected()) {
            return
        }

        this.signalServer.send(JSON.stringify({
            type: 'unregister',
            deviceId: this.deviceStore.currentDeviceId
        }))
    }

}