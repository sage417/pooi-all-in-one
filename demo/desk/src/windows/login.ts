import {BrowserWindow} from 'electron';


export const createLoginWindow = (parent: BrowserWindow, loginUrl: string) => {
    // Create the browser window.
    const loginWindow = new BrowserWindow({
        width: 4 * 320,
        height: 3 * 320,
        parent,
        modal: true,
        webPreferences: {
            // preload: path.join(__dirname, 'preload.js'),
        },
    });
    loginWindow.setMenuBarVisibility(false)

    // 监听导航事件以捕获回调
    loginWindow.webContents.on('will-redirect', (details ) => {
        const {url} = details
        console.log('did-redirect-navigation', url)
        if (url.startsWith('http://localhost:5173/#state=')) {
            parent.webContents.send('oauth-code-received', url);
            details.preventDefault()
            loginWindow.close()

        }
    });

    loginWindow.loadURL(loginUrl)

    // Open the DevTools.
    if (process.env.NODE_ENV === 'development') {
        loginWindow.webContents.openDevTools();
    }
};