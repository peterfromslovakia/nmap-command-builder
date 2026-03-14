const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

process.env.PATH = `${process.env.PATH || ''}:/usr/local/bin:/opt/homebrew/bin`;

// ─── Suppress GPU / EGL log spam ─────────────────────────────────────────────
// Disables hardware acceleration to suppress EGL driver messages that appear
// on Linux/Kali systems (e.g. "eglQueryDeviceAttribEXT: Bad attribute").
// Safe to call here — this UI has no WebGL / GPU requirements.
app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu');
app.commandLine.appendSwitch('disable-software-rasterizer');
app.commandLine.appendSwitch('disable-dev-shm-usage');
app.commandLine.appendSwitch('no-first-run');
app.commandLine.appendSwitch('disable-background-networking');

const isDev = !app.isPackaged;

let mainWindow = null;
let currentScanProcess = null;

function createWindow() {
  // Resolve icon path — platform-specific asset
  const iconFile = process.platform === 'darwin' ? 'icon.icns'
    : process.platform === 'win32'               ? 'icon.ico'
    :                                              'icon.png';
  const iconPath = path.join(__dirname, '..', 'assets', iconFile);

  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#080d08',
    icon: iconPath,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: true,
    },
    title: 'Nmap Command Builder',
    show: false,
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../build/index.html'));
  }

  mainWindow.on('closed', () => {
    if (currentScanProcess) {
      try { currentScanProcess.kill('SIGTERM'); } catch (_) {}
    }
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  // Set macOS Dock icon explicitly (uses the high-res PNG for best quality)
  if (process.platform === 'darwin' && app.dock) {
    app.dock.setIcon(path.join(__dirname, '..', 'assets', 'icon.png'));
  }
  createWindow();
});

app.on('window-all-closed', () => {
  if (currentScanProcess) {
    try { currentScanProcess.kill('SIGTERM'); } catch (_) {}
  }
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ─── IPC: Check nmap availability ───────────────────────────────────────────
ipcMain.handle('nmap:check', () => {
  return new Promise((resolve) => {
    const proc = spawn('nmap', ['--version']);
    let output = '';
    proc.stdout.on('data', (d) => { output += d.toString(); });
    proc.on('close', (code) => {
      resolve({
        available: code === 0,
        version: output.split('\n')[0]?.trim() || '',
      });
    });
    proc.on('error', () => {
      resolve({ available: false, version: '' });
    });
  });
});

// ─── IPC: Run nmap scan ───────────────────────────────────────────────────────
ipcMain.handle('nmap:run', (_event, { args }) => {
  if (currentScanProcess) {
    return { success: false, error: 'A scan is already running.' };
  }

  // Validate: must be array of strings with no shell metacharacters
  if (!Array.isArray(args) || args.some((a) => typeof a !== 'string')) {
    return { success: false, error: 'Invalid argument format.' };
  }

  const DANGEROUS = /[;&|`$(){}[\]<>!\\'"]/;
  for (const arg of args) {
    if (DANGEROUS.test(arg)) {
      return { success: false, error: `Blocked dangerous character in arg: "${arg}"` };
    }
  }

  return new Promise((resolve) => {
    try {
      currentScanProcess = spawn('nmap', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const send = (type, data) => {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('scan:output', { type, data });
        }
      };

      currentScanProcess.stdout.on('data', (d) => send('stdout', d.toString()));
      currentScanProcess.stderr.on('data', (d) => send('stderr', d.toString()));

      currentScanProcess.on('close', (code, signal) => {
        currentScanProcess = null;
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('scan:done', { code, signal });
        }
        resolve({ success: true, code, signal });
      });

      currentScanProcess.on('error', (err) => {
        currentScanProcess = null;
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('scan:error', { message: err.message });
        }
        resolve({ success: false, error: err.message });
      });
    } catch (err) {
      currentScanProcess = null;
      resolve({ success: false, error: err.message });
    }
  });
});

// ─── IPC: Kill running scan ───────────────────────────────────────────────────
ipcMain.handle('nmap:kill', () => {
  if (!currentScanProcess) return { success: false, error: 'No scan running.' };
  currentScanProcess.kill('SIGTERM');
  setTimeout(() => {
    if (currentScanProcess) {
      try { currentScanProcess.kill('SIGKILL'); } catch (_) {}
    }
  }, 2500);
  return { success: true };
});

// ─── IPC: Export result to file ───────────────────────────────────────────────
ipcMain.handle('nmap:export', async (_event, { content, defaultFilename, filters }) => {
  if (!mainWindow) return { success: false };
  const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
    defaultPath: defaultFilename || 'nmap-result.txt',
    filters: filters || [
      { name: 'Text Files', extensions: ['txt'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  if (canceled || !filePath) return { success: false, cancelled: true };
  try {
    fs.writeFileSync(filePath, content, 'utf8');
    return { success: true, filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});
