const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Check if nmap is installed and get version
  checkNmap: () => ipcRenderer.invoke('nmap:check'),

  // Detect local IPv4 networks (interface, address, CIDR)
  detectNetworks: () => ipcRenderer.invoke('net:detect'),

  // Run a scan with the given args array
  runScan: (args) => ipcRenderer.invoke('nmap:run', { args }),

  // Kill the running scan
  killScan: () => ipcRenderer.invoke('nmap:kill'),

  // Export output to a file (opens Save dialog)
  // filters: optional array of { name, extensions } for dialog type filtering
  exportResult: (content, defaultFilename, filters) =>
    ipcRenderer.invoke('nmap:export', { content, defaultFilename, filters }),

  // Open a JSON file chosen by the user (preset import) — returns its text only
  openJsonFile: () => ipcRenderer.invoke('file:openJson'),

  // Monitoring: automatic PDF report into a folder chosen in a system dialog
  monitorReportDir: () => ipcRenderer.invoke('monitor:reportDir'),
  chooseMonitorReportDir: (clear) => ipcRenderer.invoke('monitor:chooseReportDir', clear === true),
  saveMonitorReport: (html, footer, target) => ipcRenderer.invoke('monitor:saveReport', { html, footer, target }),

  // System notification (monitoring alerts)
  notify: (title, body) => ipcRenderer.invoke('app:notify', { title, body }),

  // UI language for the native menu and dialogs
  setLang: (lang) => ipcRenderer.invoke('app:setLang', lang),

  // Vulnerability intelligence: CISA KEV + EPSS (+ cached NVD), NVD detail per CVE
  intelLookup: (cves) => ipcRenderer.invoke('intel:lookup', cves),
  intelNvd: (cve) => ipcRenderer.invoke('intel:nvd', cve),

  // ARP table (MAC + vendor) for the device inventory
  getArpDevices: () => ipcRenderer.invoke('net:arp'),

  // Update check (GitHub releases) and opening the download page
  checkUpdate: () => ipcRenderer.invoke('update:check'),
  openDownload: (url) => ipcRenderer.invoke('update:open', url),

  // Render an HTML report to PDF (opens Save dialog)
  exportPdf: (html, defaultFilename, footer) =>
    ipcRenderer.invoke('report:pdf', { html, defaultFilename, footer }),

  // Listen for streamed scan output — returns cleanup function
  onScanOutput: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scan:output', handler);
    return () => ipcRenderer.removeListener('scan:output', handler);
  },

  // Listen for scan completion — returns cleanup function
  onScanDone: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scan:done', handler);
    return () => ipcRenderer.removeListener('scan:done', handler);
  },

  // Listen for scan errors — returns cleanup function
  onScanError: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scan:error', handler);
    return () => ipcRenderer.removeListener('scan:error', handler);
  },
});
