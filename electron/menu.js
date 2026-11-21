// ─── Menu aplikacie ───────────────────────────────────────────────────────────
// Odkazy v Help menu su pevne dane (ziadne URL z rendereru). DevTools a reload
// su len vo vyvojovom rezime.

const REPO = 'https://github.com/peterfromslovakia/nmap-command-builder';

const LINKS = {
  nmapDocs: 'https://nmap.org/book/man.html',
  nseDocs: 'https://nmap.org/nsedoc/',
  repo: REPO,
  releases: `${REPO}/releases/latest`,
  issues: `${REPO}/issues/new`,
};

/**
 * @param {{ isMac: boolean, isDev: boolean, appName: string, openUrl: (url: string) => void, showAbout: () => void }} o
 */
function buildMenuTemplate({ isMac, isDev, appName, openUrl, showAbout }) {
  const link = (label, key) => ({ label, click: () => openUrl(LINKS[key]) });

  const view = [
    { role: 'resetZoom' },
    { role: 'zoomIn' },
    { role: 'zoomOut' },
    { type: 'separator' },
    { role: 'togglefullscreen' },
  ];
  if (isDev) view.unshift({ role: 'reload' }, { role: 'toggleDevTools' }, { type: 'separator' });

  return [
    ...(isMac ? [{
      label: appName,
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    }] : [{
      label: 'File',
      submenu: [{ role: 'quit' }],
    }]),
    { role: 'editMenu' },
    { label: 'View', submenu: view },
    { role: 'windowMenu' },
    {
      role: 'help',
      submenu: [
        link('Nmap Reference Guide', 'nmapDocs'),
        link('NSE Script Documentation', 'nseDocs'),
        { type: 'separator' },
        link('Check for Updates…', 'releases'),
        link('Report an Issue…', 'issues'),
        link('Project on GitHub', 'repo'),
        ...(isMac ? [] : [{ type: 'separator' }, { label: `About ${appName}`, click: showAbout }]),
      ],
    },
  ];
}

module.exports = { buildMenuTemplate, LINKS };
