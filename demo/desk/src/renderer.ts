/**
 * This file will automatically be loaded by vite and run in the "renderer" context.
 * To learn more about the differences between the "main" and the "renderer" context in
 * Electron, visit:
 *
 * https://electronjs.org/docs/tutorial/process-model
 *
 * By default, Node.js integration in this file is disabled. When enabling Node.js integration
 * in a renderer process, please be aware of potential security implications. You can read
 * more about security risks here:
 *
 * https://electronjs.org/docs/tutorial/security
 *
 * To enable Node.js integration in this file, open up `main.ts` and enable the `nodeIntegration`
 * flag:
 *
 * ```
 *  // Create the browser window.
 *  mainWindow = new BrowserWindow({
 *    width: 800,
 *    height: 600,
 *    webPreferences: {
 *      nodeIntegration: true
 *    }
 *  });
 * ```
 */

import './index.css';
import {createApp} from 'vue';
import {initializeRouter} from '@/router';
import App from '@/App.vue';
import {createPinia} from 'pinia'
import VueKeyCloak, {VueKeycloakInstance} from '@dsb-norge/vue-keycloak-js'

console.log('👋 This message is being logged by "renderer.ts", included via Vite');

const app = createApp(App)
    .use(createPinia())
    .use(VueKeyCloak, {
        config: {
            realm: 'pooi',
            url: 'https://keycloak.pooi.app',
            clientId: 'desk_spa',
        },
        init: {
            onLoad: 'login-required',
            checkLoginIframe: true,
            // silentCheckSsoRedirectUri: `${location.origin}/silent-check-sso.html`,
            redirectUri: 'http://localhost/keycloak-redirect', // fix err_unsafe_redirect
            enableLogging: true,
            pkceMethod: "S256",
            responseMode: 'query'  // confilt with vue-route see:https://github.com/dsb-norge/vue-keycloak-js/issues/94
        },

        async onReady(keycloak: VueKeycloakInstance) {
            console.log('keycloak ready, authenticated:', keycloak.authenticated)
            // if (!keycloak.authenticated) {
            //     window.electronAPI.ipcRendererSend('require-open-login-window', await keycloak.createLoginUrl())
            // }
            // mount after keycloak ready
            app.use(initializeRouter(keycloak)).mount('#app');

        }
    })

