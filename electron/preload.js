const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Check if nmap is installed and get version
  checkNmap: () => ipcRenderer.invoke('nmap:check'),

  // Run a scan with the given args array
  runScan: (args) => ipcRenderer.invoke('nmap:run', { args }),

  // Kill the running scan
  killScan: () => ipcRenderer.invoke('nmap:kill'),

  // Export output to a file (opens Save dialog)
  // filters: optional array of { name, extensions } for dialog type filtering
  exportResult: (content, defaultFilename, filters) =>
    ipcRenderer.invoke('nmap:export', { content, defaultFilename, filters }),

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
