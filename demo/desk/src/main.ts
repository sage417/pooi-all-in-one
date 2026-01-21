import {app, BrowserWindow, desktopCapturer, ipcMain, session} from 'electron';
import started from 'electron-squirrel-startup';
import {computeDeviceFingerprint} from '@/utils/system'
import {createMainWindow} from '@/windows/index';
import {createControlWindow} from '@/windows/control';
import {createLoginWindow} from '@/windows/login';
import {handleKeyboardData} from '@/utils/winInput';
import path from 'node:path';

// check koffi
// import koffi from 'koffi';
// koffi.load('user32.dll')

let targetDeviceId = ''


// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (started) {
  app.quit();
}

const setDisplayMediaRequestHandler = () => {
  session.defaultSession.setDisplayMediaRequestHandler((request, callback) => {
    desktopCapturer.getSources({ types: ['screen'] }).then((sources) => {
      // Grant access to the first screen found.
      callback({ video: sources[0], audio: 'loopback' })
    })
    // If true, use the system picker if available.
    // Note: this is currently experimental. If the system picker
    // is available, it will be used and the media request handler
    // will not be invoked.
  }, { useSystemPicker: true })
}



// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.on('ready', async () => {

  const currentDeviceId = await computeDeviceFingerprint()
  ipcMain.handle('device-fingerprint', () => currentDeviceId)

  ipcMain.on('require-open-control-window', (_, deviceId: string) => {
    targetDeviceId = deviceId
    createControlWindow(targetDeviceId)
  })
  ipcMain.on('require-open-login-window', (_, loginUrl: string) => {
    createLoginWindow(mainWindow, loginUrl)
  })
  ipcMain.on('simulate-keyevent', (_, data: ArrayBuffer) => {
    handleKeyboardData(data)
  })

  setDisplayMediaRequestHandler()

  session.defaultSession.webRequest.onBeforeRequest({
    urls: [
      'http://localhost/keycloak-redirect*'
    ]
  }, (details, callback) => {
    const { url } = details;
    const { search, } = new URL(url);

    const targetWin = BrowserWindow.getAllWindows()
      .find(win => win.webContents.id === details.webContentsId && !win.isDestroyed());

    const hash = targetWin === mainWindow ? '' : `#/remote-control/${targetDeviceId}`

    if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
      const redirectURL = `${MAIN_WINDOW_VITE_DEV_SERVER_URL}/${search}${hash}`
      callback({ redirectURL });
    } else {

      callback({ cancel: true });

      targetWin.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`), { hash, search })
        .catch(err => console.error('loadFile err:', err))
    }
  })

  const mainWindow = createMainWindow();
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  if (BrowserWindow.getAllWindows().length === 0) {
    createMainWindow();
  }
});


// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and import them here.