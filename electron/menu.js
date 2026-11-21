// ─── Menu aplikacie ───────────────────────────────────────────────────────────
// Odkazy v Help menu su pevne dane (ziadne URL z rendereru). DevTools a reload
// su len vo vyvojovom rezime.

const REPO = 'https://github.com/peterfromslovakia/nmap-command-builder';

const LINKS = {
  nmapDocs: 'https://nmap.org/book/man.html',
  nseDocs: 'https://nmap.org/nsedoc/',
  repo: REPO,
  issues: `${REPO}/issues/new`,
};

// Texty menu a dialogov v hlavnom procese (systemove polozky prekladá OS sám).
const MENU_TEXT = {
  en: {
    file: 'File', view: 'View', nmapDocs: 'Nmap Reference Guide', nseDocs: 'NSE Script Documentation',
    updates: 'Check for Updates…', issue: 'Report an Issue…', repo: 'Project on GitHub', about: (n) => `About ${n}`,
    updErr: 'Could not check for updates', updLatest: 'You have the latest version',
    updAvail: (v) => `Version ${v} is available`, updHave: (v) => `You have ${v}.`, updFile: (f) => `Download: ${f}`,
    download: 'Download', notes: 'Release Notes', later: 'Later',
    openData: 'Open Data Folder', clearData: 'Delete All Saved Data…',
    clearTitle: 'Delete all saved data?',
    clearDetail: 'This deletes saved scans (comparison), my presets, report details, the monitoring schedule, the vulnerability database cache, the language and window settings.\n\nExported reports and files are not affected. This cannot be undone.',
    clearYes: 'Delete', cancel: 'Cancel', cleared: 'All saved data was deleted.',
  },
  sk: {
    file: 'Súbor', view: 'Zobrazenie', nmapDocs: 'Príručka Nmap', nseDocs: 'Dokumentácia skriptov NSE',
    updates: 'Skontrolovať aktualizácie…', issue: 'Nahlásiť problém…', repo: 'Projekt na GitHube', about: (n) => `O aplikácii ${n}`,
    updErr: 'Aktualizácie sa nepodarilo skontrolovať', updLatest: 'Máte najnovšiu verziu',
    updAvail: (v) => `Je k dispozícii verzia ${v}`, updHave: (v) => `Máte ${v}.`, updFile: (f) => `Stiahnuť: ${f}`,
    download: 'Stiahnuť', notes: 'Čo je nové', later: 'Neskôr',
    openData: 'Otvoriť priečinok s dátami', clearData: 'Vymazať všetky uložené dáta…',
    clearTitle: 'Vymazať všetky uložené dáta?',
    clearDetail: 'Vymažú sa uložené skeny (porovnanie), moje predvoľby, údaje do reportu, plán monitorovania, uložená databáza zraniteľností, jazyk a nastavenie okna.\n\nExportované reporty a súbory sa nezmenia. Vrátiť sa to nedá.',
    clearYes: 'Vymazať', cancel: 'Zrušiť', cleared: 'Všetky uložené dáta boli vymazané.',
  },
};
const menuText = (lang) => MENU_TEXT[lang] || MENU_TEXT.en;

/**
 * @param {{ isMac: boolean, isDev: boolean, appName: string, openUrl: (url: string) => void, showAbout: () => void, checkUpdates: () => void }} o
 */
function buildMenuTemplate({ isMac, isDev, appName, openUrl, showAbout, checkUpdates, openDataFolder = () => {}, clearData = () => {}, lang = 'en' }) {
  const T = menuText(lang);
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
      label: T.file,
      submenu: [{ role: 'quit' }],
    }]),
    { role: 'editMenu' },
    { label: T.view, submenu: view },
    { role: 'windowMenu' },
    {
      role: 'help',
      submenu: [
        link(T.nmapDocs, 'nmapDocs'),
        link(T.nseDocs, 'nseDocs'),
        { type: 'separator' },
        { label: T.updates, click: () => checkUpdates() },
        link(T.issue, 'issues'),
        link(T.repo, 'repo'),
        { type: 'separator' },
        { label: T.openData, click: () => openDataFolder() },
        { label: T.clearData, click: () => clearData() },
        ...(isMac ? [] : [{ type: 'separator' }, { label: T.about(appName), click: showAbout }]),
      ],
    },
  ];
}

module.exports = { buildMenuTemplate, menuText, LINKS };
