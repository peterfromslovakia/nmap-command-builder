const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const { detectNetworks } = require('./network');
const { validateArgs } = require('./argsValidator');

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


// ─── Security helpers ────────────────────────────────────────────────────────

// Whitelist prepinacov a validacia argumentov: pozri ./argsValidator.js

// IPC smie volat len nase vlastne okno (nie iny frame ani cudzi web content).
function isTrusted(event) {
  if (!mainWindow || mainWindow.isDestroyed()) return false;
  if (event.sender !== mainWindow.webContents) return false;
  const url = (event.senderFrame && event.senderFrame.url) || '';
  if (isDev) return url.startsWith('http://localhost:3000');
  return url.startsWith('file://');
}

const EXPORT_MAX_BYTES = 20 * 1024 * 1024;
const EXPORT_EXTS = new Set(['.txt', '.json', '.csv', '.md']);

// Rozdeli stream na cele riadky; nedokonceny zvysok drzi, kym nepride dalsi chunk.
function createLineBuffer(emit) {
  let rest = '';
  return {
    push(chunk) {
      rest += chunk;
      const idx = rest.lastIndexOf('\n');
      if (idx === -1) return;
      emit(rest.slice(0, idx + 1));
      rest = rest.slice(idx + 1);
    },
    flush() {
      if (rest) emit(rest);
      rest = '';
    },
  };
}

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
      sandbox: true,
      webSecurity: true,
    },
    title: 'Nmap Command Builder',
    show: false,
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Lockdown: ziadne nove okna, navigacia mimo appky ani webview.
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (e, url) => {
    const allowed = isDev ? url.startsWith('http://localhost:3000') : url.startsWith('file://');
    if (!allowed) e.preventDefault();
  });
  mainWindow.webContents.on('will-attach-webview', (e) => e.preventDefault());

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
  // Appka nepotrebuje kameru, mikrofon, polohu ani notifikacie.
  const { session } = require('electron');
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);

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
ipcMain.handle('nmap:check', (event) => {
  if (!isTrusted(event)) return { available: false, version: '' };
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

// ─── IPC: Detect local networks ──────────────────────────────────────────────
ipcMain.handle('net:detect', (event) => {
  if (!isTrusted(event)) return [];
  try { return detectNetworks(); } catch (_) { return []; }
});

// ─── IPC: Run nmap scan ───────────────────────────────────────────────────────
ipcMain.handle('nmap:run', (event, payload) => {
  if (!isTrusted(event)) return { success: false, error: 'Untrusted sender.' };
  const args = payload && payload.args;
  if (currentScanProcess) {
    return { success: false, error: 'A scan is already running.' };
  }

  // Whitelist prepinacov (viď ALLOWED_FLAGS); chyba = sken sa nespusti.
  const argError = validateArgs(args);
  if (argError) return { success: false, error: argError };

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

      const outBuf = createLineBuffer((t) => send('stdout', t));
      const errBuf = createLineBuffer((t) => send('stderr', t));
      currentScanProcess.stdout.setEncoding('utf8');
      currentScanProcess.stderr.setEncoding('utf8');
      currentScanProcess.stdout.on('data', (d) => outBuf.push(d));
      currentScanProcess.stderr.on('data', (d) => errBuf.push(d));

      currentScanProcess.on('close', (code, signal) => {
        outBuf.flush();
        errBuf.flush();
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
ipcMain.handle('nmap:kill', (event) => {
  if (!isTrusted(event)) return { success: false, error: 'Untrusted sender.' };
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
ipcMain.handle('nmap:export', async (event, payload) => {
  if (!isTrusted(event)) return { success: false, error: 'Untrusted sender.' };
  const { content, defaultFilename } = payload || {};
  if (typeof content !== 'string' || Buffer.byteLength(content, 'utf8') > EXPORT_MAX_BYTES) {
    return { success: false, error: 'Invalid or too large export content.' };
  }
  const safeName = path.basename(String(defaultFilename || 'nmap-result.txt'));
  const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
    defaultPath: safeName,
    filters: [
      { name: 'Text / JSON / CSV / Markdown', extensions: ['txt', 'json', 'csv', 'md'] },
    ],
  });
  if (canceled || !filePath) return { success: false, cancelled: true };
  if (!EXPORT_EXTS.has(path.extname(filePath).toLowerCase())) {
    return { success: false, error: 'Only .txt, .json, .csv and .md exports are allowed.' };
  }
  try {
    fs.writeFileSync(filePath, content, 'utf8');
    return { success: true, filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ─── IPC: Export report as PDF ────────────────────────────────────────────────
// Renderer posle hotove HTML reportu (hodnoty uz escapovane). Vykresli sa v
// skrytom okne bez JavaScriptu, bez preloadu a bez moznosti navigacie; HTML
// ma CSP default-src 'none', takze nenacita nic zo siete.
ipcMain.handle('report:pdf', async (event, payload) => {
  if (!isTrusted(event)) return { success: false, error: 'Untrusted sender.' };
  const { html, defaultFilename } = payload || {};
  if (typeof html !== 'string' || Buffer.byteLength(html, 'utf8') > EXPORT_MAX_BYTES) {
    return { success: false, error: 'Invalid or too large report.' };
  }
  const safeName = path.basename(String(defaultFilename || 'nmap-report.pdf'));
  const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
    defaultPath: safeName,
    filters: [{ name: 'PDF', extensions: ['pdf'] }],
  });
  if (canceled || !filePath) return { success: false, cancelled: true };
  if (path.extname(filePath).toLowerCase() !== '.pdf') {
    return { success: false, error: 'Only .pdf files are allowed.' };
  }

  const tmpFile = path.join(app.getPath('temp'), `nmap-report-${process.pid}-${Date.now()}.html`);
  let win = null;
  try {
    fs.writeFileSync(tmpFile, html, 'utf8');
    win = new BrowserWindow({
      show: false,
      webPreferences: { javascript: false, sandbox: true, contextIsolation: true, nodeIntegration: false },
    });
    win.webContents.on('will-navigate', (e) => e.preventDefault());
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    await win.loadFile(tmpFile);
    const pdf = await win.webContents.printToPDF({ pageSize: 'A4', printBackground: true });
    fs.writeFileSync(filePath, pdf);
    return { success: true, filePath };
  } catch (err) {
    return { success: false, error: err.message };
  } finally {
    if (win && !win.isDestroyed()) win.destroy();
    fs.rm(tmpFile, { force: true }, () => {});
  }
});
