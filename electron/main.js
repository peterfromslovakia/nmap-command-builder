const { app, BrowserWindow, ipcMain, dialog, Menu, shell, screen, net } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const { detectNetworks } = require('./network');
const { validateArgs } = require('./argsValidator');
const { readState, resolveBounds, writeState } = require('./windowState');
const { buildMenuTemplate, menuText } = require('./menu');
const { checkForUpdate, isDownloadUrl } = require('./updates');
const { arpDevices } = require('./arp');
const { defaultGateway } = require('./gateway');
const { VulnIntel } = require('./vulnIntel');

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

  const stateFile = path.join(app.getPath('userData'), 'window-state.json');
  const bounds = resolveBounds(
    readState(stateFile),
    [screen.getPrimaryDisplay(), ...screen.getAllDisplays()].map((d) => d.workArea),
    { width: 1440, height: 920, minWidth: 1100, minHeight: 700 }
  );

  mainWindow = new BrowserWindow({
    x: bounds.x,
    y: bounds.y,
    width: bounds.width,
    height: bounds.height,
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
    if (bounds.maximized) mainWindow.maximize();
    mainWindow.show();
  });
  mainWindow.on('close', () => writeState(stateFile, mainWindow));

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

// Jazyk menu a dialogov hlavneho procesu (nastavuje renderer prepinacom EN/SK).
let uiLang = 'en';
function setMenu(lang) {
  Menu.setApplicationMenu(Menu.buildFromTemplate(buildMenuTemplate({
    isMac: process.platform === 'darwin',
    isDev,
    appName: 'Nmap Command Builder',
    openUrl: (url) => shell.openExternal(url),
    showAbout: () => app.showAboutPanel(),
    checkUpdates: () => checkUpdatesInteractive(),
    lang,
  })));
}

// Systemove upozornenie (monitorovanie). Text je obycajny retazec s obmedzenou dlzkou;
// kliknutie len prenesie okno aplikacie do popredia.
ipcMain.handle('app:notify', (event, payload) => {
  if (!isTrusted(event) || !payload || typeof payload !== 'object') return false;
  const { Notification } = require('electron');
  if (!Notification.isSupported()) return false;
  // eslint-disable-next-line no-control-regex -- riadiace znaky z textu upozornenia odstranujeme zamerne
  const clip = (v, n) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f]/g, ' ').slice(0, n) : '');
  const n = new Notification({ title: clip(payload.title, 120) || 'Nmap Command Builder', body: clip(payload.body, 400), silent: false });
  n.on('click', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });
  n.show();
  if (process.platform === 'darwin' && app.dock) app.dock.bounce('informational');
  return true;
});

// Nacitanie JSON suboru zvoleneho pouzivatelom (import predvolieb).
// Renderer nedostane cestu, len obsah; max. 256 KB.
ipcMain.handle('file:openJson', async (event) => {
  if (!isTrusted(event)) return { ok: false, error: 'Untrusted sender.' };
  const r = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [{ name: 'JSON', extensions: ['json'] }],
  });
  if (r.canceled || !r.filePaths[0]) return { ok: false, cancelled: true };
  try {
    const st = fs.statSync(r.filePaths[0]);
    if (!st.isFile() || st.size > 256 * 1024) return { ok: false, error: 'File is too large.' };
    return { ok: true, text: fs.readFileSync(r.filePaths[0], 'utf8') };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('app:setLang', (event, lang) => {
  if (!isTrusted(event) || (lang !== 'en' && lang !== 'sk')) return false;
  if (lang !== uiLang) { uiLang = lang; setMenu(lang); }
  return true;
});

app.whenReady().then(() => {
  // Appka nepotrebuje kameru, mikrofon, polohu ani notifikacie.
  const { session } = require('electron');
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);

  // Set macOS Dock icon explicitly (uses the high-res PNG for best quality)
  if (process.platform === 'darwin' && app.dock) {
    app.dock.setIcon(path.join(__dirname, '..', 'assets', 'icon.png'));
  }
  app.setAboutPanelOptions({
    applicationName: 'Nmap Command Builder',
    applicationVersion: app.getVersion(),
    copyright: '© 2026 Peter Obala · MIT License',
    website: 'https://github.com/peterfromslovakia/nmap-command-builder',
  });
  setMenu(uiLang);
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
        privileged: isPrivileged(),
      });
    });
    proc.on('error', () => {
      resolve({ available: false, version: '' });
    });
  });
});

// Root na macOS/Linuxe. Na Windows nmap pouziva Npcap a raw skeny funguju
// aj bez spustenia ako spravca, preto sa tam nic neupravuje.
function isPrivileged() {
  if (process.platform === 'win32') return true;
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

// ─── IPC: Detect local networks ──────────────────────────────────────────────
// ─── Informacie o zranitelnostiach (CISA KEV, EPSS, NVD) ─────────────────────
let vulnIntel = null;
const intel = () => {
  if (!vulnIntel) {
    vulnIntel = new VulnIntel({ dir: path.join(app.getPath('userData'), 'intel'), fetchFn: (u, o) => net.fetch(u, o) });
  }
  return vulnIntel;
};

ipcMain.handle('intel:lookup', async (event, cves) => {
  if (!isTrusted(event)) return null;
  return intel().lookup(cves);
});

ipcMain.handle('intel:nvd', async (event, cve) => {
  if (!isTrusted(event)) return { ok: false, error: 'Untrusted sender.' };
  return intel().nvd(cve);
});

// MAC adresy + vyrobcovia z ARP tabulky (po skene siete; funguje bez root).
ipcMain.handle('net:arp', async (event) => {
  if (!isTrusted(event)) return [];
  try { return await arpDevices(); } catch (_) { return []; }
});

ipcMain.handle('net:gateway', async (event) => {
  if (!isTrusted(event)) return null;
  try { return await defaultGateway(); } catch (_) { return null; }
});

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
// ─── Aktualizacie ────────────────────────────────────────────────────────────

const runUpdateCheck = () => checkForUpdate(app.getVersion(), { fetchFn: (u, o) => net.fetch(u, o) });

// Help → Check for Updates…: vysledok v systemovom dialogu.
async function checkUpdatesInteractive() {
  const r = await runUpdateCheck();
  const win = mainWindow || undefined;
  const T = menuText(uiLang);
  if (!r.ok) {
    await dialog.showMessageBox(win, { type: 'warning', message: T.updErr, detail: r.error });
  } else if (!r.available) {
    await dialog.showMessageBox(win, { type: 'info', message: T.updLatest, detail: `Nmap Command Builder ${r.current}` });
  } else {
    const actions = r.asset ? ['download', 'notes', 'later'] : ['notes', 'later'];
    const { response } = await dialog.showMessageBox(win, {
      type: 'info',
      message: T.updAvail(r.latest),
      detail: `${T.updHave(r.current)}${r.asset ? ` ${T.updFile(r.asset.name)}` : ''}`,
      buttons: actions.map((a) => T[a]), defaultId: 0, cancelId: actions.length - 1,
    });
    const choice = actions[response];
    if (choice === 'download') shell.openExternal(r.asset.url);
    if (choice === 'notes') shell.openExternal(r.pageUrl);
  }
}

ipcMain.handle('update:check', async (event) => {
  if (!isTrusted(event)) return { ok: false, error: 'Untrusted sender.' };
  return runUpdateCheck();
});

// Otvori v prehliadaci len odkaz na vydanie tohto projektu na GitHube.
ipcMain.handle('update:open', async (event, url) => {
  if (!isTrusted(event) || !isDownloadUrl(url)) return { ok: false };
  await shell.openExternal(url);
  return { ok: true };
});

// Pata kazdej strany PDF: nazov reportu, kto test vykonal, cislo strany.
// Texty prichadzaju z rendereru → orezat a escapovat.
function pdfFooterTemplate(footer) {
  const esc = (v) => String(v ?? '').slice(0, 120)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const f = footer && typeof footer === 'object' ? footer : {};
  const left = [f.title || 'Nmap Scan Report', f.tester].filter(Boolean).map(esc).join(' · ');
  return `<div style="font-family:Helvetica,Arial,sans-serif;font-size:7.5px;color:#777;width:100%;padding:0 14mm;display:flex;justify-content:space-between">`
    + `<span>${left}</span><span>${esc(f.page || 'Page')} <span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`;
}

/** HTML → PDF v skrytom okne bez JavaScriptu (report je uz escapovany). */
async function renderPdf(html, footer) {
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
    return await win.webContents.printToPDF({
      pageSize: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: '<span></span>',
      footerTemplate: pdfFooterTemplate(footer),
      margins: { top: 0.6, bottom: 0.75, left: 0.55, right: 0.55 },
    });
  } finally {
    if (win && !win.isDestroyed()) win.destroy();
    fs.rm(tmpFile, { force: true }, () => {});
  }
}

// ─── Automaticke reporty z monitorovania ─────────────────────────────────────
// Priecinok vyberie pouzivatel v dialogu; cestu drzi len main proces (renderer
// ju nevie zmenit ani podvrhnut) a nazov suboru sklada main proces.
const monitorPrefsFile = () => path.join(app.getPath('userData'), 'monitor-reports.json');
const readReportDir = () => {
  try {
    const d = JSON.parse(fs.readFileSync(monitorPrefsFile(), 'utf8')).dir;
    return typeof d === 'string' && path.isAbsolute(d) && fs.statSync(d).isDirectory() ? d : '';
  } catch (_) { return ''; }
};

ipcMain.handle('monitor:reportDir', (event) => (isTrusted(event) ? { dir: readReportDir() } : { dir: '' }));

ipcMain.handle('monitor:chooseReportDir', async (event, clear) => {
  if (!isTrusted(event)) return { dir: '' };
  if (clear === true) { fs.rm(monitorPrefsFile(), { force: true }, () => {}); return { dir: '' }; }
  const r = await dialog.showOpenDialog(mainWindow, { properties: ['openDirectory', 'createDirectory'] });
  if (r.canceled || !r.filePaths[0]) return { dir: readReportDir(), cancelled: true };
  fs.writeFileSync(monitorPrefsFile(), JSON.stringify({ dir: r.filePaths[0] }));
  return { dir: r.filePaths[0] };
});

ipcMain.handle('monitor:saveReport', async (event, payload) => {
  if (!isTrusted(event)) return { success: false, error: 'Untrusted sender.' };
  const dir = readReportDir();
  if (!dir) return { success: false, error: 'No report folder chosen.' };
  const { html, footer, target } = payload || {};
  if (typeof html !== 'string' || Buffer.byteLength(html, 'utf8') > EXPORT_MAX_BYTES) {
    return { success: false, error: 'Invalid or too large report.' };
  }
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}`;
  const safeTarget = String(target || 'scan').replace(/[^A-Za-z0-9.-]+/g, '_').slice(0, 60) || 'scan';
  const filePath = path.join(dir, `nmap-monitor-${safeTarget}-${stamp}.pdf`);
  try {
    fs.writeFileSync(filePath, await renderPdf(html, footer));
    return { success: true, filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('report:pdf', async (event, payload) => {
  if (!isTrusted(event)) return { success: false, error: 'Untrusted sender.' };
  const { html, defaultFilename, footer } = payload || {};
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

  try {
    fs.writeFileSync(filePath, await renderPdf(html, footer));
    return { success: true, filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});
