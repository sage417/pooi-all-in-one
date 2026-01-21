import {BrowserWindow} from 'electron';
import path from 'node:path';

export const createControlWindow = (deviceId: string) => {
    // Create the browser window.
    const controlWindow = new BrowserWindow({
        width: 4 * 320,
        height: 3 * 320,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
        },
    });
    controlWindow.setMenuBarVisibility(false)

    controlWindow.webContents.on('did-start-navigation', (details) => {
        const { url } = details
        console.log('Navigation started:', url);
    });

    controlWindow.webContents.on('will-navigate', (details) => {
        const { url } = details
        console.log('will-navigate:', url);
    })

    controlWindow.webContents.on('will-redirect', (details) => {
        const { url } = details
        console.log('will-redirect:', url);
    })

    // and load the control.html of the app.
    if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
        controlWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL + `#/remote-control/${deviceId}`);
    } else {
        controlWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`), {
            hash: `/remote-control/${deviceId}`
        });
    }

    // Open the DevTools.
    if (process.env.NODE_ENV === 'development') {
        controlWindow.webContents.openDevTools();
    }
};