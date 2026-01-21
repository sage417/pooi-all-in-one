import {BrowserWindow} from 'electron';
import path from 'node:path';

export const createMainWindow = () => {
    // Create the browser window.
    const mainWindow = new BrowserWindow({
        width: 4 * 230,
        height: 3 * 230,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
        },
    });
    mainWindow.resizable = false

    const { session: { webRequest } } = mainWindow.webContents;

    // webRequest.onHeadersReceived((details, callback) => {
    //     callback({
    //         responseHeaders: {
    //             ...details.responseHeaders,
    //             'Content-Security-Policy': [
    //                 'default-src \'self\'; connect-src \'self\' https://keycloak.pooi.app ws://192.168.2.122:8080; frame-src \'self\' https://keycloak.pooi.app http://localhost; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\'',
    //             ]
    //         }
    //     })
    // })


    

    mainWindow.webContents.on('did-start-navigation', (details) => {
        const { url } = details
        console.log('did-start-navigation:', url);
    });

    mainWindow.webContents.on('will-navigate', (details) => {
        const { url } = details
        console.log('will-navigate:', url);
    })

    mainWindow.webContents.on('will-redirect', (details) => {
        const { url } = details
        console.log('will-redirect:', url);
    })


    // and load the index.html of the app.
    if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
        mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
    } else {
        mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`))
    }

    // Open the DevTools.
    if (process.env.NODE_ENV === 'development') {
        mainWindow.webContents.openDevTools();
    }

    return mainWindow
};