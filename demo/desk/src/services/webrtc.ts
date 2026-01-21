import {useDeviceStore} from '../stores/devices';
import {useSignalStore} from '../stores/signal'
import {useKeycloak, VueKeycloakInstance} from '@dsb-norge/vue-keycloak-js';
import {DeepReadonly} from 'vue';
import {SignalMessage, SignalServer} from './signalService';


// 消息头结构 (2字节)
enum ChannelType {
  Mouse = 0x01,
  Keyboard = 0x02,
  Clipboard = 0x03,
  Command = 0xFF
}

// 鼠标事件数据结构（固定14字节）
interface MouseEventBinary {
  type: number;        // 1字节 (0: move, 1: down, 2: up, 3: wheel)
  x: number;           // 2字节 (0-65535 归一化坐标)
  y: number;           // 2字节
  buttons: number;     // 1字节 (按钮掩码)
  delta: number;       // 2字节 (滚轮增量 ±32767)
  // 剩余6字节预留
}

// 键盘事件数据结构（固定8字节）
interface KeyEventBinary {
  type: number;        // 1字节 (0: down, 1: up)
  keyCode: number;     // 2字节
  modifiers: number;   // 1字节 (ctrl:0x01, shift:0x02, alt:0x04, meta: 0x8)
  // 剩余4字节预留
}

// 类型定义
export interface WebRTCServiceOptions {
  deviceId: string;
  onConnect: (info: RemoteConnectionInfo) => void;
  onDisconnect: () => void;
  onError: (error: Error) => void;
  onRemoteStream: (stream: MediaStream) => void;
}

export interface RemoteConnectionInfo {
  deviceId: string;
  deviceName: string;
  os: string;
  resolution: string;
}

export interface MouseEventData {
  type: 'mousedown' | 'mouseup' | 'mousemove' | 'mousewheel';
  x: number;
  y: number;
  button?: number;
  buttons?: number;
  deltaX?: number;
  deltaY?: number;
  deltaZ?: number;
  deltaMode?: number;
}

export interface KeyEventData {
  type: 'keydown' | 'keyup';
  key: string,
  code: string;
  keyCode: number;
  location: number;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  metaKey: boolean;
}

export interface SpecialKeysCommand {
  command: string;
}

export interface ClipboardData {
  text: string;
}

export class WebRTCService {
  // private socket: Socket | null = null;
  private signalServer: SignalServer | null = null;
  private signalStore = useSignalStore()
  private deviceStore = useDeviceStore()
  private peerConnection: RTCPeerConnection | null = null;
  private dataChannel: RTCDataChannel | null = null;
  private remoteStream: MediaStream | null = null;
  private options: WebRTCServiceOptions;
  private isControlEnabled: boolean = true;
  private lastMouseMoveTime: number = 0;
  private mouseMoveThrottleMs: number = 16; // 约60fps
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 500;
  private reconnectTimeoutMs: number = 3000;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingInterval: ReturnType<typeof setInterval> | null = null;
  private candidateCache: SignalMessage[] = []

  private MOUSE_BUFFER_POOL = new ArrayBuffer(14);
  private KEY_BUFFER_POOL = new ArrayBuffer(4);

  private keycloak: DeepReadonly<VueKeycloakInstance> | null = null;


  constructor(options: WebRTCServiceOptions) {
    this.keycloak = useKeycloak()
    this.options = options;
    this.signalServer = this.signalStore.signalServer as SignalServer
  }

  /**
   * 初始化并建立WebRTC连接
   */
  public async connect(): Promise<void> {
    try {
      this.signalServer.onIceCandidate(async message => {
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
      })
      this.signalServer.onAnswer(async message => {
        if (this.peerConnection?.localDescription) {
          await this.peerConnection.setRemoteDescription(message.sdp)
          console.log('set remote:', message.sdp)
        }
      })
      this.signalStore.start()
      // await this.setupSocketConnection();
      this.setupPeerConnection();
      await this.createOffer()
      // this.setupPingInterval();
      if (this.options.onConnect) {
        this.options.onConnect({
          deviceId: this.options.deviceId,
          deviceName: '',
          os: '',
          resolution: ''
        })
      }
    } catch (error) {
      this.handleError(error instanceof Error ? error : new Error('连接失败'));
    }
  }

  /**
   * 断开连接
   */
  public disconnect(): void {
    this.cleanup();
    this.options.onDisconnect();
  }

  /**
   * 启用远程控制
   */
  public enableControl(): void {
    this.isControlEnabled = true;
    this.sendControlCommand({ type: 'enableControl' });
  }

  /**
   * 禁用远程控制
   */
  public disableControl(): void {
    this.isControlEnabled = false;
    this.sendControlCommand({ type: 'disableControl' });
  }

  /**
   * 发送鼠标移动事件
   */
  public sendMouseMove(x: number, y: number): void {

    const now = Date.now();
    if (now - this.lastMouseMoveTime < this.mouseMoveThrottleMs) {
      return;
    }

    this.lastMouseMoveTime = now;

    const view = new DataView(this.MOUSE_BUFFER_POOL);
    view.setUint8(0, 0); // 类型: move
    view.setUint16(1, x, true); // 小端字节序
    view.setUint16(3, y, true);
    view.setUint8(5, 0)
    view.setUint16(6, 0, true);

    this.sendControlData(ChannelType.Mouse, this.MOUSE_BUFFER_POOL);
  }

  /**
   * 发送鼠标事件
   */
  public sendMouseEvent(type: 'mousedown' | 'mouseup', event: MouseEvent): void {
    if (!this.isControlEnabled) return;

    if (!this.remoteStream) return;

    const videoElement = document.querySelector('video') as HTMLVideoElement;
    if (!videoElement) return;

    const rect = videoElement.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width;
    const y = (event.clientY - rect.top) / rect.height;

    const data: MouseEventData = {
      type,
      x,
      y,
      button: event.button,
      buttons: event.buttons
    };

    const view = new DataView(this.MOUSE_BUFFER_POOL);
    view.setUint8(0, type === 'mousedown' ? 1 : 2); // 类型: down, up
    view.setUint16(1, x, true); // 小端字节序
    view.setUint16(3, y, true);
    view.setUint8(5, event.buttons)
    view.setUint16(6, 0, true);

    this.sendControlData(ChannelType.Mouse, this.MOUSE_BUFFER_POOL);
  }
  /**
   * 发送滚轮事件
   */
  public sendWheelEvent(event: WheelEvent): void {
    if (!this.isControlEnabled) return;

    const videoElement = document.querySelector('video') as HTMLVideoElement;
    if (!videoElement) return;

    const rect = videoElement.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width;
    const y = (event.clientY - rect.top) / rect.height;

    const data: MouseEventData = {
      type: 'mousewheel',
      x,
      y,
      deltaX: event.deltaX,
      deltaY: event.deltaY,
      deltaZ: event.deltaZ,
      deltaMode: event.deltaMode
    };

    const view = new DataView(this.MOUSE_BUFFER_POOL);
    view.setUint8(0, 3); // 类型: wheel
    view.setUint16(1, x, true); // 小端字节序
    view.setUint16(3, y, true);
    view.setUint8(5, event.buttons)
    view.setUint16(6, 0, true);

    this.sendControlData(ChannelType.Mouse, this.MOUSE_BUFFER_POOL);
  }

  /**
   * 发送键盘事件
   */
  public sendKeyEvent(type: 'keydown' | 'keyup', event: KeyboardEvent): void {
    const view = new DataView(this.KEY_BUFFER_POOL);

    view.setUint8(0, type === 'keydown' ? 0 : 1);
    view.setUint16(1, event.keyCode, true);
    view.setUint8(3,
      (event.ctrlKey ? 0x01 : 0) |
      (event.shiftKey ? 0x02 : 0) |
      (event.altKey ? 0x04 : 0) |
      (event.metaKey ? 0x08 : 0)
    );

    this.sendControlData(ChannelType.Keyboard, this.KEY_BUFFER_POOL);
  }

  /**
   * 发送特殊按键组合
   */
  public sendSpecialKeys(command: string): void {
    if (!this.isControlEnabled) return;

    const data: SpecialKeysCommand = {
      command
    };

    this.sendControlData(ChannelType.Command, data);
  }

  /**
   * 发送剪贴板内容
   */
  public async sendClipboardContent(text: string): Promise<void> {
    if (!this.isControlEnabled) return;

    const data: ClipboardData = {
      text
    };

    this.sendControlData(ChannelType.Clipboard, data);
  }

  /**
   * 设置WebRTC对等连接
   */
  private setupPeerConnection(): void {
    if (this.peerConnection) {
      this.peerConnection.close()
    }
    const configuration: RTCConfiguration = {
      iceServers: []
    }

    this.peerConnection = new RTCPeerConnection(configuration)
    console.log('new RTCPeerConnection')

    // after setLocalDescription
    this.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {

        if (!this.signalServer || this.signalServer.readyState() !== WebSocket.OPEN) {
          return
        }

        const webrtcCandidate: SignalMessage = {
          type: 'webrtc:ice-candidate',
          targetDeviceId: this.options.deviceId,
          deviceId: this.deviceStore.currentDeviceId,
          fromDeviceId: this.deviceStore.currentDeviceId,
          sdp: event.candidate
        }

        this.signalServer.send(webrtcCandidate)
      }
    };

    this.peerConnection.onicecandidateerror = (event) => {
      console.error('peer connection onicecandidateerror', event)
    }

    this.peerConnection.oniceconnectionstatechange = (event) => {
      console.log('oniceconnectionstatechange:', event);

      if (this.peerConnection?.iceConnectionState === 'disconnected' ||
        this.peerConnection?.iceConnectionState === 'failed') {
        this.handleError(new Error('WebRTC连接失败'));
      }
    };

    this.peerConnection.onsignalingstatechange = (event) => {
      console.log('onsignalingstatechange:', event);
    }

    this.peerConnection.ontrack = (event) => {
      console.log('peer connection ontrack', event);

      if (event.streams && event.streams[0]) {
        this.remoteStream = event.streams[0];
        this.options.onRemoteStream(this.remoteStream);
      }
    };

    this.dataChannel = this.peerConnection.createDataChannel('control', {
      ordered: true,
      maxRetransmits: 0,
      protocol: 'binary',
    });
    this.dataChannel.binaryType = 'arraybuffer';

    this.dataChannel.addEventListener('open', () => {
      console.log('control channel opened')
    })

    this.dataChannel.addEventListener('close', (event) => {
      console.log('control channel closed', event)
    })

    this.dataChannel.addEventListener('error', (event) => {
      console.log('control channel error', event)
    })

    this.dataChannel.addEventListener('message', (event) => {
      console.log('control channel message', event.data)
    })
  }


  private setupDataChannel(): void {
    if (!this.peerConnection) return;

    this.dataChannel = this.peerConnection.createDataChannel('control', {
      ordered: true,
      maxRetransmits: 0,
      maxPacketLifeTime: 1000,
      protocol: 'binary',
    });
    this.dataChannel.binaryType = 'arraybuffer';

    this.dataChannel.addEventListener('open', () => {
      console.log('control channel opened')
    })

    this.dataChannel.addEventListener('close', (event) => {
      console.log('control channel closed', event)
    })

    this.dataChannel.addEventListener('error', (event) => {
      console.log('control channel error', event)
    })

    this.dataChannel.addEventListener('message', (event) => {
      console.log('control channel message', event.data)
    })

    // this.dataChannel.onmessage = (event) => {
    //   try {
    //     const message = JSON.parse(event.data);
    //     this.handleDataChannelMessage(message);
    //   } catch (error) {
    //     console.error('解析数据通道消息失败:', error);
    //   }
    // };

    // this.peerConnection.ondatachannel = (event) => {
    //   const receiveChannel = event.channel;

    //   receiveChannel.onmessage = (event) => {
    //     try {
    //       const message = JSON.parse(event.data);
    //       this.handleDataChannelMessage(message);
    //     } catch (error) {
    //       console.error('解析数据通道消息失败:', error);
    //     }
    //   };
    // };
  }

  /**
   * [controller] 1) create and send offer 
   */
  private async createOffer(): Promise<void> {
    if (!this.peerConnection) return;

    try {
      const offer = await this.peerConnection.createOffer({
        offerToReceiveAudio: false,
        offerToReceiveVideo: true
      });

      await this.peerConnection.setLocalDescription(offer);

      this.signalServer?.send({
        type: 'webrtc:offer',
        targetDeviceId: this.options.deviceId,
        deviceId: this.deviceStore.currentDeviceId,
        fromDeviceId: this.deviceStore.currentDeviceId,
        sdp: offer
      });
    } catch (error) {
      this.handleError(error instanceof Error ? error : new Error('创建offer失败'));
    }
  }

  /**
   * sendControlData
   * 
   * @param channel 
   * @param data 
   * @returns 
   */
  private sendControlData(channel: ChannelType, data: ArrayBuffer): void {
    if (!this.dataChannel || this.dataChannel.readyState !== 'open') return;

    const header = new Uint8Array([channel]);
    const message = new Uint8Array(header.byteLength + data.byteLength);
    message.set(header, 0);
    message.set(new Uint8Array(data), header.byteLength);

    try {
      this.dataChannel.send(message.buffer);
    } catch (error) {
      console.error('dataChannel send controll data err:', error);
    }
  }


  /**
   * 发送控制命令
   */
  private sendControlCommand(command: { type: string, [key: string]: any }): void {
    this.sendControlData(ChannelType.Command, command);
  }

  /**
   * 处理数据通道消息
   */
  private handleDataChannelMessage(message: any): void {
    if (!message || !message.channel) return;

    switch (message.channel) {
      case 'status':
        console.log('状态消息:', message.data);
        break;

      case 'clipboard':
        if (message.data && message.data.text) {
          navigator.clipboard.writeText(message.data.text)
            .catch(error => console.error('写入剪贴板失败:', error));
        }
        break;

      case 'error':
        console.error('远程错误:', message.data);
        break;

      default:
        console.log('未知通道消息:', message);
    }
  }
  /**
   * 设置心跳检测
   */
  private setupPingInterval(): void {
    // 清除可能存在的之前的心跳检测
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
    }

    // 每30秒发送一次心跳
    this.pingInterval = setInterval(() => {
      if (this.signalServer) {
        this.signalServer.send({ type: 'ping', deviceId: this.options.deviceId });
      }
    }, 30000);
  }

  /**
   * 处理重连
   */
  private handleReconnect(rejectCallback?: (error: Error) => void): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.handleError(new Error('重连次数超过上限，连接失败'));
      if (rejectCallback) {
        rejectCallback(new Error('重连次数超过上限，连接失败'));
      }
      return;
    }

    this.reconnectAttempts++;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    console.log(`尝试重连 (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);

    this.reconnectTimer = setTimeout(() => {
      this.cleanup(false);
      this.connect().catch((error) => {
        console.error('重连失败:', error);
        this.handleReconnect(rejectCallback);
      });
    }, this.reconnectTimeoutMs);
  }

  /**
   * 处理错误
   */
  private handleError(error: Error): void {
    console.error('WebRTC 服务错误:', error);
    this.options.onError(error);
  }

  /**
   * 清理资源
   */
  private cleanup(emitDisconnect: boolean = true): void {
    // 清理心跳检测
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }

    // 清理重连定时器
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    // 关闭数据通道
    if (this.dataChannel) {
      this.dataChannel.close();
      this.dataChannel = null;
    }

    // 关闭对等连接
    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }

    // 关闭远程流
    if (this.remoteStream) {
      this.remoteStream.getTracks().forEach(track => track.stop());
      this.remoteStream = null;
    }

    // 断开 Socket.IO 连接
    if (this.signalServer) {
      if (emitDisconnect) {
        this.signalServer.send({ type: 'unregister', deviceId: this.options.deviceId });
      }
      this.signalServer.close()
      this.signalServer = null;
    }
  }
}