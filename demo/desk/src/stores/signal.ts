// src/stores/signal.ts

import {defineStore} from 'pinia';
import {SignalServer} from '@/services/signalService';

export const useSignalStore = defineStore('signal', {
  state: () => ({
    signalServer: null as SignalServer | null,
  }),

  actions: {
    initialize(serverUrl: string) {
      if (!this.signalServer) {
        this.signalServer = new SignalServer(serverUrl);
      }
    },
    async start() {
      await this.signalServer.start();
    },
    close() {
      this.signalServer?.close();
      this.signalServer = null;
    },
  },
});