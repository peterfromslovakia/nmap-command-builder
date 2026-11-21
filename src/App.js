import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import './App.css';

import { FLAG_CATEGORIES } from './data/flags';
import { buildCommand, parseScanSummary } from './utils/commandBuilder';
import { validateTarget } from './utils/validator';
import { toggleScript, removeScripts, addScriptArg } from './utils/nseSelection';
import { buildReportModel, toMarkdown, toHtml, pdfFooterLabel } from './utils/report';
import { loadReportMeta, saveReportMeta } from './utils/reportMeta';
import ReportDialog from './components/ReportDialog';
import UpdateBanner from './components/UpdateBanner';
import { loadUpdatePrefs, saveUpdatePrefs, shouldAutoCheck, shouldShowBanner } from './utils/updatePrefs';
import { elevationBlockers, rootRequirements } from './utils/privileges';
import { makeSnapshot, loadSnapshots, saveSnapshot, clearSnapshots, comparisonFor } from './utils/scanDiff';

import CommandPreview from './components/CommandPreview';
import BuilderTab from './components/BuilderTab';
import CheatsheetTab from './components/CheatsheetTab';
import PresetsTab from './components/PresetsTab';
import ScriptsTab from './components/ScriptsTab';
import EthicsTab from './components/EthicsTab';
import TerminalOutput from './components/TerminalOutput';
import ScanHistory from './components/ScanHistory';
import PortsPanel from './components/PortsPanel';
import HostInfoPanel from './components/HostInfoPanel';
import NetworkMap from './components/NetworkMap';
import FollowUpPanel from './components/FollowUpPanel';
import IntelPanel from './components/IntelPanel';
import FindingsPanel from './components/FindingsPanel';
import DiffPanel from './components/DiffPanel';
import { loadUserPresets, saveUserPreset, deleteUserPreset, exportUserPresets, importUserPresets } from './utils/userPresets';
import { loadLabels, saveLabels, setLabel } from './utils/deviceLabels';
import { FLAG_MAP } from './data/flags';
import { matchShortcut, shortcutHints } from './utils/shortcuts';
import { DISCOVERY_MODES, buildInventory, inventoryCsv } from './utils/inventory';
import { parseFindings } from './utils/findings';
import { useLang } from './i18n/ui';
import { collectCves, applyIntel, loadIntelEnabled, saveIntelEnabled } from './utils/intel';
import MonitorBar from './components/MonitorBar';
import { loadMonitor, saveMonitor, startMonitor, monitorDue, markRun, monitorChanges } from './utils/monitor';
import InventoryPanel from './components/InventoryPanel';
import ToolsTab from './components/ToolsTab';

const IS_MAC = typeof navigator !== 'undefined' && /Mac/i.test(navigator.userAgent);

// ─── Initial state for expanded categories ────────────────────────────────────
const initExpanded = () => {
  const s = {};
  FLAG_CATEGORIES.forEach((c) => { s[c.id] = c.safe; });
  return s;
};

const MAX_OUTPUT_CHUNKS = 5000; // strop terminalu (zobrazenie) pri dlhych skenoch (-p-)
// Analyza (inventar, mapa, nalezy, report) pracuje s celym vystupom, nie len so
// zobrazenou castou — inak by pri sieti s tisickami zariadeni vypadli prve.
const MAX_ANALYSIS_BYTES = 64 * 1024 * 1024;

// Nastavi/odstrani jednu hodnotu flagu (prazdna hodnota = flag sa odstrani).
function setFlagValue(selections, id, value) {
  const next = { ...selections };
  if (value) next[id] = value; else delete next[id];
  return next;
}

// ─── Parse target from a saved command string (for history reload) ────────────
function parseCommandToTarget(command) {
  const parts = command.replace(/^nmap\s+/, '').trim().split(/\s+/);
  for (let i = parts.length - 1; i >= 0; i--) {
    if (!parts[i].startsWith('-')) return parts[i];
  }
  return '';
}

export default function App() {
  const { lang, setLang, t } = useLang();
  const tRef = useRef(t);
  tRef.current = t;
  useEffect(() => { window.electronAPI?.setLang?.(lang); document.documentElement.lang = lang; }, [lang]);
  // ── Nmap availability ──────────────────────────────────────────────────────
  const [nmapStatus, setNmapStatus] = useState({ checked: false, available: false, version: '' });

  // ── Builder state ──────────────────────────────────────────────────────────
  const [target, setTarget] = useState('');
  const [networks, setNetworks] = useState([]);
  const targetTouchedRef = useRef(false); // true ak uzivatel upravil target rucne
  const [flagSelections, setFlagSelections] = useState({});
  const [advancedMode, setAdvancedMode] = useState(false);

  // ── UI state ───────────────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState('builder');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedCategories, setExpandedCategories] = useState(initExpanded);
  const [copied, setCopied] = useState(false);

  // ── Scan state ─────────────────────────────────────────────────────────────
  const [scanStatus, setScanStatus] = useState('idle'); // idle|scanning|done|error|killed
  const [outputLines, setOutputLines] = useState([]);
  // Cely vystup skenu (terminal zobrazuje len poslednych MAX_OUTPUT_CHUNKS blokov).
  const fullOutRef = useRef({ chunks: [], bytes: 0, truncated: false });
  const resetFullOutput = (text = '') => { fullOutRef.current = { chunks: text ? [text] : [], bytes: text.length, truncated: false }; };
  const [scanHistory, setScanHistory] = useState([]);
  const [scannedTarget, setScannedTarget] = useState('');

  // ── Saved scan snapshots (for "changes since previous scan") ─────────────
  const [snapshots, setSnapshots] = useState(() => loadSnapshots());
  const [currentSnapshot, setCurrentSnapshot] = useState(null);
  const [update, setUpdate] = useState(null);
  const [reportDialog, setReportDialog] = useState(null); // 'pdf' | 'md' | null
  const [reportMeta, setReportMeta] = useState(() => loadReportMeta());
  const [inventory, setInventory] = useState(null);
  const [deviceLabels, setDeviceLabels] = useState(() => { try { return loadLabels(); } catch (_) { return { byMac: {}, byIp: {} }; } });
  const [gateway, setGateway] = useState(null); // predvolena brana systemu (mapa siete)
  // Aktualne informacie o zranitelnostiach k nalezom posledneho skenu.
  const [intelEnabled, setIntelEnabled] = useState(() => loadIntelEnabled());
  const [intelData, setIntelData] = useState(null); // { kev, epss, nvd, meta }
  const [intelLoading, setIntelLoading] = useState(false);
  const [nvdProgress, setNvdProgress] = useState({ done: 0, total: 0 });
  const [discoverMode, setDiscoverMode] = useState('quick'); // zariadenia po skene siete
  const scanKindRef = useRef('scan');
  const lastScanRef = useRef(null); // { args, command, target } posledneho spusteneho skenu
  const [monitor, setMonitor] = useState(() => loadMonitor());
  const [clock, setClock] = useState(() => Date.now());
  const monitorHandledRef = useRef(0);
  const busyRef = useRef(false); // sken bezi (synchronne, bez cakania na render)
  const emptyScanIdRef = useRef(0); // sken bez najdenych zariadeni (snimka sa neulozi)
  const [userPresets, setUserPresets] = useState(() => loadUserPresets());
  const [diffBaselineId, setDiffBaselineId] = useState(null); // null = najnovsi predchadzajuci sken
  useEffect(() => { setDiffBaselineId(null); }, [currentSnapshot]);
  const comparison = useMemo(
    () => comparisonFor(snapshots, currentSnapshot, diffBaselineId),
    [snapshots, currentSnapshot, diffBaselineId]
  );
  const scanIdRef = useRef(0);
  const savedScanIdRef = useRef(0);

  // ── Refs for closures in IPC callbacks ────────────────────────────────────
  const currentCommandRef = useRef('');
  const targetRef = useRef('');

  // Keep targetRef in sync
  useEffect(() => { targetRef.current = target; }, [target]);

  // ── Derived: build the current command ────────────────────────────────────
  const { args, command, warnings, requiresRoot, hasTarget } = buildCommand(
    target,
    flagSelections,
    advancedMode
  );

  // Bez rootu sa prikaz NEMENI, len sa ukaze, ktore flagy root potrebuju.
  const noRoot = nmapStatus.checked && nmapStatus.privileged === false;
  const rootNeeds = useMemo(
    () => (noRoot ? rootRequirements(flagSelections) : []),
    [noRoot, flagSelections]
  );

  // macOS: semafor okna (hiddenInset) prekryva lavu cast hlavicky
  useEffect(() => {
    if (/Mac/i.test(navigator.userAgent)) document.body.classList.add('platform-mac');
  }, []);

  // ── Detect local network (on mount + whenever the window regains focus) ───
  const refreshNetworks = useCallback(async () => {
    if (!window.electronAPI || !window.electronAPI.detectNetworks) return;
    const list = await window.electronAPI.detectNetworks();
    setNetworks(list);
    window.electronAPI.getGateway?.().then((gw) => setGateway(gw || null)).catch(() => {});
    // Auto-predefine target, kym ho uzivatel nezmenil rucne
    if (list.length > 0 && !targetTouchedRef.current) {
      setTarget(list[0].suggested);
    }
  }, []);

  useEffect(() => {
    refreshNetworks();
    window.addEventListener('focus', refreshNetworks);
    return () => window.removeEventListener('focus', refreshNetworks);
  }, [refreshNetworks]);

  // Rucna uprava targetu vypne automaticke prepisovanie
  const handleTargetChange = useCallback((v) => {
    targetTouchedRef.current = true;
    setTarget(v);
  }, []);

  const handleUseNetwork = useCallback((cidr) => {
    targetTouchedRef.current = false; // vyber zo zoznamu = znova automaticky rezim
    setTarget(cidr);
  }, []);

  // ── Check nmap on mount ───────────────────────────────────────────────────
  useEffect(() => {
    if (!window.electronAPI) {
      setNmapStatus({ checked: true, available: false, version: 'Electron API not found' });
      return;
    }
    window.electronAPI.checkNmap().then((result) => {
      setNmapStatus({ checked: true, ...result });
    });
  }, []);

  // ── Register IPC listeners once ───────────────────────────────────────────
  useEffect(() => {
    if (!window.electronAPI) return;

    const cleanOutput = window.electronAPI.onScanOutput((data) => {
      const full = fullOutRef.current;
      if (full.bytes < MAX_ANALYSIS_BYTES) { full.chunks.push(String(data.data || '')); full.bytes += String(data.data || '').length; }
      setOutputLines((prev) => {
        const next = [
          ...prev,
          { id: Date.now() + Math.random(), type: data.type, text: data.data },
        ];
        if (next.length > MAX_OUTPUT_CHUNKS) { fullOutRef.current.truncated = true; return next.slice(-MAX_OUTPUT_CHUNKS); }
        return next;
      });
    });

    const cleanDone = window.electronAPI.onScanDone((data) => {
      busyRef.current = false;
      setScanStatus(data.signal ? 'killed' : 'done');
      const statusMsg = data.signal
        ? `\n[⊗ ${tRef.current('Scan killed — signal: {signal}', { signal: data.signal })}]`
        : `\n[✓ ${tRef.current('Scan completed — exit code: {code}', { code: data.code ?? 0 })}]`;
      setOutputLines((prev) => [
        ...prev,
        { id: Date.now(), type: 'system', text: statusMsg },
      ]);
      setScanHistory((prev) => [
        {
          command: currentCommandRef.current,
          time: new Date().toISOString(),
          exitCode: data.code,
          signal: data.signal,
          status: data.signal ? 'killed' : data.code === 0 ? 'success' : 'error',
        },
        ...prev,
      ].slice(0, 10));
    });

    const cleanError = window.electronAPI.onScanError((data) => {
      busyRef.current = false;
      setScanStatus('error');
      setOutputLines((prev) => [
        ...prev,
        { id: Date.now(), type: 'error', text: `\n[✗ ${tRef.current('Scan error: {msg}', { msg: data.message })}]` },
      ]);
    });

    return () => {
      cleanOutput();
      cleanDone();
      cleanError();
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleFlagChange = useCallback((flagId, value) => {
    setFlagSelections((prev) => {
      if (value === false || value === null || value === undefined || value === '') {
        const next = { ...prev };
        delete next[flagId];
        return next;
      }
      return { ...prev, [flagId]: value };
    });
  }, []);

  // ── NSE script library: upravuje hodnoty flagov 'script' a 'script_args' ──
  const handleToggleScript = useCallback((name) => {
    setFlagSelections((prev) => setFlagValue(prev, 'script', toggleScript(prev.script, name)));
  }, []);

  const handleRemoveScripts = useCallback((names) => {
    setFlagSelections((prev) => setFlagValue(prev, 'script', removeScripts(prev.script, names)));
  }, []);

  const handleClearScripts = useCallback(() => {
    setFlagSelections((prev) => setFlagValue(setFlagValue(prev, 'script', ''), 'script_args', ''));
  }, []);

  const handleAddScriptArg = useCallback((key, example) => {
    setFlagSelections((prev) =>
      setFlagValue(prev, 'script_args', addScriptArg(prev.script_args, key, example)));
  }, []);

  const handleToggleCategory = useCallback((catId) => {
    setExpandedCategories((prev) => ({ ...prev, [catId]: !prev[catId] }));
  }, []);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }, [command]);

  const handleClear = useCallback(() => {
    targetTouchedRef.current = false;
    setTarget('');
    setFlagSelections({});
    setSearchQuery('');
    refreshNetworks(); // po vycisteni sa target znova predvyplni detegovanou sietou
  }, [refreshNetworks]);

  const handleLoadPreset = useCallback((preset) => {
    setFlagSelections(preset.flags || {});
    // Vlastny preset: ulozeny target ma prednost; ADV flagy si vyziadaju ADV rezim.
    if (preset.created !== undefined) {
      if (preset.target) { targetTouchedRef.current = true; setTarget(preset.target); }
      if (Object.keys(preset.flags).some((id) => FLAG_MAP[id] && !FLAG_MAP[id].safe)) setAdvancedMode(true);
      setActiveTab('builder');
      return;
    }
    // Predvoleny target z presetu (napr. 192.168.1.0/24) len ako zaloha:
    // ak mame detegovanu siet, ostava ta (napr. 192.168.50.0/24).
    if (preset.target && networks.length === 0) {
      targetTouchedRef.current = true;
      setTarget(preset.target);
    }
    setActiveTab('builder');
  }, [networks]);

  const handleSaveUserPreset = useCallback((name, withTarget) => {
    const r = saveUserPreset({ name, flags: flagSelections, target: withTarget ? target : '' });
    setUserPresets(r.list);
    return r;
  }, [flagSelections, target]);

  const handleExportPresets = useCallback(() => {
    window.electronAPI.exportResult(exportUserPresets(userPresets), `nmap-presets-${new Date().toISOString().slice(0, 10)}.json`, [{ name: 'JSON', extensions: ['json'] }]);
  }, [userPresets]);

  const handleImportPresets = useCallback(async () => {
    const f = await window.electronAPI.openJsonFile();
    if (!f || !f.ok) return f && !f.cancelled ? { ok: false, error: f.error } : null;
    const r = importUserPresets(f.text);
    if (r.ok) setUserPresets(r.list);
    return r;
  }, []);

  const handleScanDevice = useCallback((ip) => { targetTouchedRef.current = true; setTarget(ip); setActiveTab('presets'); }, []);
  const localIps = useMemo(() => networks.map((n) => n.address), [networks]);

  const handleDeleteUserPreset = useCallback((id) => {
    setUserPresets(deleteUserPreset(id));
  }, []);

  const handleLoadFromHistory = useCallback((entry) => {
    const t = parseCommandToTarget(entry.command);
    if (t) { targetTouchedRef.current = true; setTarget(t); }
    setActiveTab('builder');
  }, []);

  // Spolocne spustenie skenu (RUN SCAN aj PREHLADAT SIET).
  const startScan = useCallback(async ({ args: scanArgs, command: scanCommand, target: scanTarget, kind = 'scan', needs = [], elevated = false }) => {
    if (!window.electronAPI) return;
    if (scanStatus === 'scanning' || busyRef.current) return;
    if (!validateTarget(scanTarget).valid) return;
    busyRef.current = true;

    setScanStatus('scanning');
    scanIdRef.current = Date.now();
    scanKindRef.current = kind;
    lastScanRef.current = { args: scanArgs, command: scanCommand, target: scanTarget, elevated };
    setInventory(null);
    setCurrentSnapshot(null);
    currentCommandRef.current = scanCommand;
    setScannedTarget(scanTarget);

    const ts = new Date().toLocaleTimeString();
    resetFullOutput(`[${ts}] $ ${scanCommand}\n`);
    setOutputLines([
      ...(kind === 'monitor' ? [{ id: Date.now() - 1, type: 'system', text: `[${ts}] ⟳ ${tRef.current('Monitoring — scheduled repeat of the scan')}\n` }] : []),
      { id: Date.now(), type: 'system', text: `[${ts}] ${elevated ? '#' : '$'} ${scanCommand}\n` },
      ...(elevated ? [{ id: Date.now() + 2, type: 'system', text: `[${ts}] 🔒 ${tRef.current('Running with administrator rights — enter your password in the system dialog.')}\n` }] : []),
      ...(!elevated && needs.some((r) => r.effect === 'quits')
        ? [{ id: Date.now() + 1, type: 'error', text: `[!] ${tRef.current('Not running as root: {flags} need root, nmap will stop. Start the app with sudo.', { flags: needs.filter((r) => r.effect === 'quits').map((r) => r.flag).join(' ') })}\n` }]
        : []),
    ]);

    const res = await window.electronAPI.runScan(scanArgs, { elevated });
    if (res && res.success === false) {
      busyRef.current = false;
      setScanStatus('error');
      setOutputLines((prev) => [
        ...prev,
        { id: Date.now(), type: 'error', text: `\n[✗ ${tRef.current('Scan not started: {msg}', { msg: res.error })}]` },
      ]);
    }
  }, [scanStatus]);

  const handleRunScan = useCallback(
    () => startScan({ args, command, target, needs: rootNeeds }),
    [startScan, args, command, target, rootNeeds]
  );

  // Spustit ten isty prikaz s pravami spravcu (systemove okno na heslo).
  const elevateBlocked = useMemo(() => elevationBlockers(args), [args]);
  const handleRunElevated = useCallback(
    () => startScan({ args, command, target, elevated: true }),
    [startScan, args, command, target]
  );

  // ── Prehladat siet jednym tlacidlom ──────────────────────────────────────
  // Ciel: aktualny ciel, ak je to rozsah (CIDR / interval); inak detegovana siet.
  const discoveryTarget = useMemo(() => {
    const t = target.trim();
    if (t && /[/-]/.test(t) && validateTarget(t).valid) return t;
    return networks[0]?.suggested || '';
  }, [target, networks]);

  const handleDiscoverNetwork = useCallback((mode, opts = {}) => {
    const flags = DISCOVERY_MODES[mode].flags;
    const built = buildCommand(discoveryTarget, flags, advancedMode);
    targetTouchedRef.current = true;
    setTarget(discoveryTarget);
    setFlagSelections(flags);
    setActiveTab('builder');
    startScan({ args: built.args, command: built.command, target: discoveryTarget, kind: 'discovery', elevated: Boolean(opts.elevated) });
  }, [discoveryTarget, advancedMode, startScan]);

  const handleKillScan = useCallback(async () => {
    if (!window.electronAPI) return;
    setScanStatus('killed');
    await window.electronAPI.killScan();
  }, []);

  // Text dokonceneho skenu pre analyzu (cely vystup).
  const scanText = useMemo(() => {
    if (scanStatus !== 'done' && scanStatus !== 'killed') return '';
    return fullOutRef.current.truncated ? fullOutRef.current.chunks.join('') : outputLines.map((l) => l.text || '').join('');
  }, [scanStatus, outputLines]);
  // Panely s vysledkami dostanu cely vystup, aj ked terminal zobrazuje len koniec.
  const analysisLines = useMemo(
    () => (fullOutRef.current.truncated && scanText ? [{ id: 'full', type: 'stdout', text: scanText }] : outputLines),
    [outputLines, scanText]
  );

  // Po dokonceni skenu ulozi snimku vysledkov (len ak nasiel nejake hosty).
  useEffect(() => {
    if (scanStatus !== 'done' || savedScanIdRef.current === scanIdRef.current || !scanIdRef.current) return;
    savedScanIdRef.current = scanIdRef.current;
    const snap = makeSnapshot({
      id: scanIdRef.current,
      time: new Date().toISOString(),
      target: scannedTarget,
      command: currentCommandRef.current,
      text: scanText,
    });
    if (snap.hosts.length === 0) { emptyScanIdRef.current = scanIdRef.current; return; }
    setSnapshots(saveSnapshot(snap));
    setCurrentSnapshot(snap);
  }, [scanStatus, scanText, scannedTarget]);

  // ── Monitorovanie: opakovanie skenu v intervale + upozornenie na zmeny ───
  useEffect(() => {
    const id = setInterval(() => setClock(Date.now()), 15000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!monitorDue(monitor, clock, scanStatus === 'scanning')) return;
    const next = saveMonitor(markRun(monitor, Date.now()));
    setMonitor(next);
    startScan({ args: monitor.args, command: monitor.command, target: monitor.target, kind: 'monitor' });
  }, [clock, monitor, scanStatus, startScan]);

  // Automaticky PDF report z monitorovania (pri prvom behu a pri zmenach),
  // do priecinka, ktory si pouzivatel vybral v systemovom dialogu.
  const [reportDir, setReportDir] = useState('');
  useEffect(() => {
    window.electronAPI?.monitorReportDir?.().then((r) => setReportDir((r && r.dir) || '')).catch(() => {});
  }, []);
  const handleChooseReportDir = useCallback(async (clear) => {
    const r = await window.electronAPI.chooseMonitorReportDir(clear === true);
    setReportDir((r && r.dir) || '');
  }, []);
  const autoReportRef = useRef(null);
  autoReportRef.current = async (cmp, target) => {
    if (!reportDir) return;
    const meta = reportMeta.saved ? reportMeta : { ...reportMeta, lang };
    const model = reportModelRef.current(meta, cmp);
    const res = await window.electronAPI.saveMonitorReport(toHtml(model), pdfFooterLabel(model), target);
    const T = tRef.current;
    setOutputLines((prev) => [...prev, res && res.success
      ? { id: Date.now(), type: 'system', text: `\n[✓ ${T('PDF report saved to: {path}', { path: res.filePath })}]` }
      : { id: Date.now(), type: 'error', text: `\n[✗ ${T('PDF export failed: {msg}', { msg: T((res && res.error) || 'unknown error') })}]` }]);
  };

  // Vysledok monitorovaneho behu: porovnanie s predchadzajucim skenom toho isteho ciela.
  useEffect(() => {
    if (scanKindRef.current !== 'monitor' || !monitor || monitorHandledRef.current === scanIdRef.current) return;
    if (scanStatus === 'scanning' || scanStatus === 'idle') return;
    const finish = (lastResult, lastCounts) => {
      monitorHandledRef.current = scanIdRef.current;
      setMonitor((m) => (m ? saveMonitor({ ...m, lastResult, lastCounts: lastCounts || m.lastCounts }) : m));
    };
    if (scanStatus === 'error' || scanStatus === 'killed') { finish('error'); return; }
    if (currentSnapshot && currentSnapshot.id === scanIdRef.current) {
      const cmp = comparisonFor(snapshots, currentSnapshot);
      if (!cmp) { finish('first'); autoReportRef.current(null, monitor.target); return; }
      const { alert, counts } = monitorChanges(cmp.diff);
      finish(alert ? 'changes' : 'nochange', counts);
      if (alert) {
        autoReportRef.current(cmp, monitor.target);
        const T = tRef.current;
        const parts = [
          counts.findings && T('{n} new vulnerabilities', { n: counts.findings }),
          counts.ports && T('{n} new open ports', { n: counts.ports }),
          counts.hosts && T('{n} new devices', { n: counts.hosts }),
        ].filter(Boolean).join(', ');
        window.electronAPI?.notify?.(T('Changes in {target}', { target: monitor.target }), parts);
        setMonitor((m) => (m ? saveMonitor({ ...m, alerts: m.alerts + 1 }) : m));
      }
    } else if (emptyScanIdRef.current === scanIdRef.current) {
      finish('nohosts');
    }
  }, [scanStatus, currentSnapshot, snapshots, monitor]);

  const handleStartMonitor = useCallback((intervalMin) => {
    if (!lastScanRef.current) return;
    setMonitor(saveMonitor(startMonitor({ ...lastScanRef.current, intervalMin })));
  }, []);
  const handleStopMonitor = useCallback(() => setMonitor(saveMonitor(null)), []);
  const handleMonitorNow = useCallback(() => {
    if (!monitor || scanStatus === 'scanning') return;
    setMonitor(saveMonitor(markRun(monitor, Date.now())));
    startScan({ args: monitor.args, command: monitor.command, target: monitor.target, kind: 'monitor' });
  }, [monitor, scanStatus, startScan]);

  // Po skene: inventar zariadeni (+ MAC / vyrobca z ARP tabulky systemu).
  useEffect(() => {
    if (scanStatus !== 'done' && scanStatus !== 'killed') return undefined;
    const text = scanText;
    const own = { selfIps: localIps, platform: nmapStatus.platform || (IS_MAC ? 'darwin' : '') };
    const base = buildInventory(text, [], own);
    if (base.length === 0 || (base.length < 2 && scanKindRef.current !== 'discovery')) return undefined;
    let alive = true;
    setInventory(base);
    (window.electronAPI?.getArpDevices?.() || Promise.resolve([])).then((arp) => {
      if (alive) setInventory(buildInventory(text, arp, own));
    });
    return () => { alive = false; };
  }, [scanStatus]); // eslint-disable-line react-hooks/exhaustive-deps -- staci pri zmene stavu skenu (scanText sa meni s nim)

  // Nalezy posledneho skenu (+ KEV / EPSS / NVD).
  const rawFindings = useMemo(() => (scanText ? parseFindings(scanText) : []), [scanText]);
  const findings = useMemo(() => applyIntel(rawFindings, intelEnabled ? intelData : null), [rawFindings, intelData, intelEnabled]);
  const findingsCves = useMemo(() => collectCves(rawFindings).join(','), [rawFindings]);

  useEffect(() => {
    setIntelData(null);
    setNvdProgress({ done: 0, total: 0 });
    const api = window.electronAPI;
    if (!intelEnabled || !findingsCves || !api?.intelLookup) return undefined;
    let alive = true;
    const cves = findingsCves.split(',');
    (async () => {
      setIntelLoading(true);
      const base = await api.intelLookup(cves);
      if (!alive) return;
      setIntelLoading(false);
      if (!base) return;
      setIntelData(base);
      // NVD detaily postupne (limit NVD bez kluca); najprv aktivne zneuzivane, max. 25 CVE.
      const todo = cves
        .filter((c) => !base.nvd[c])
        .sort((a, b) => Number(Boolean(base.kev[b])) - Number(Boolean(base.kev[a])) || (base.epss[b]?.epss ?? 0) - (base.epss[a]?.epss ?? 0))
        .slice(0, 25);
      setNvdProgress({ done: 0, total: todo.length });
      for (let i = 0; i < todo.length && alive; i++) {
        const r = await api.intelNvd(todo[i]);
        if (!alive) return;
        if (r && r.ok) setIntelData((prev) => (prev ? { ...prev, nvd: { ...prev.nvd, [todo[i]]: r.data } } : prev));
        setNvdProgress({ done: i + 1, total: todo.length });
      }
    })();
    return () => { alive = false; };
  }, [findingsCves, intelEnabled]);

  const handleToggleIntel = useCallback(() => {
    setIntelEnabled((on) => { saveIntelEnabled(!on); return !on; });
  }, []);

  const handleClearSnapshots = useCallback(() => {
    setSnapshots(clearSnapshots());
    setCurrentSnapshot(null);
  }, []);

  // Datovy model reportu z aktualneho skenu (export aj automaticke reporty monitorovania).
  const reportModelRef = useRef(null);
  reportModelRef.current = (meta, cmp = comparison) => {
    const rawText = scanText || outputLines.map((l) => l.text || '').join('');
    return buildReportModel({
      text: rawText,
      command: currentCommandRef.current,
      target: scannedTarget || targetRef.current,
      timestamp: new Date(currentSnapshot?.time || Date.now()).toLocaleString(),
      generatedAt: new Date().toLocaleString(),
      nmapVersion: nmapStatus.version,
      meta,
      findings: scanText === rawText ? findings : undefined,
      intelMeta: intelEnabled && intelData ? intelData.meta : null,
      inventory,
      labels: deviceLabels,
      gatewayIp: gateway,
      localIps,
      comparison: cmp && {
        baselineTime: new Date(cmp.baseline.time).toLocaleString(),
        baselineCommand: cmp.baseline.command,
        diff: cmp.diff,
      },
    });
  };

  const handleLabelChange = useCallback((mac, ip, name) => {
    setDeviceLabels((prev) => {
      const next = setLabel(mac, ip, name, prev);
      saveLabels(next);
      return next;
    });
  }, []);

  // ── Unified export handler — supports txt / json / csv ────────────────────
  const handleExport = useCallback(async (format = 'txt', meta = null) => {
    if (!window.electronAPI) return;
    // Report (PDF / MD): najprv udaje o teste a jazyk.
    if ((format === 'pdf' || format === 'md') && !meta) { setReportDialog(format); return; }

    const rawText = scanText || outputLines.map((l) => l.text || '').join('');
    const { openPorts } = parseScanSummary(analysisLines);
    const ts = new Date().toISOString();
    const stamp = Date.now();

    let content, filename, filters;

    if (format === 'md' || format === 'pdf') {
      const model = reportModelRef.current(meta);
      if (format === 'pdf') {
        const res = await window.electronAPI.exportPdf(toHtml(model), `nmap-report-${model.lang}-${stamp}.pdf`, pdfFooterLabel(model));
        setOutputLines((prev) => [
          ...prev,
          res.success
            ? { id: Date.now(), type: 'system', text: `\n[✓ ${tRef.current('PDF report saved to: {path}', { path: res.filePath })}]` }
            : res.cancelled ? null : { id: Date.now(), type: 'error', text: `\n[✗ ${tRef.current('PDF export failed: {msg}', { msg: res.error })}]` },
        ].filter(Boolean));
        return;
      }
      content = toMarkdown(model);
      filename = `nmap-report-${model.lang}-${stamp}.md`;
      filters = [{ name: 'Markdown', extensions: ['md'] }];
    } else if (format === 'json') {
      const data = {
        command: currentCommandRef.current,
        target: targetRef.current,
        timestamp: ts,
        openPorts: openPorts.map((p) => ({
          port: p.port,
          protocol: p.proto,
          service: p.service || '',
          version: p.version || '',
        })),
        raw: rawText,
      };
      content = JSON.stringify(data, null, 2);
      filename = `nmap-${stamp}.json`;
      filters = [
        { name: 'JSON Files', extensions: ['json'] },
        { name: 'All Files', extensions: ['*'] },
      ];
    } else if (format === 'csv') {
      const header = 'port,protocol,service,version';
      const rows = openPorts.map((p) =>
        `${p.port},${p.proto},${p.service || ''},${(p.version || '').replace(/,/g, ';')}`
      );
      content = [header, ...rows].join('\n');
      filename = `nmap-${stamp}.csv`;
      filters = [
        { name: 'CSV Files', extensions: ['csv'] },
        { name: 'All Files', extensions: ['*'] },
      ];
    } else {
      content = rawText;
      filename = `nmap-${stamp}.txt`;
      filters = [
        { name: 'Text Files', extensions: ['txt'] },
        { name: 'All Files', extensions: ['*'] },
      ];
    }

    const result = await window.electronAPI.exportResult(content, filename, filters);
    if (result.success) {
      setOutputLines((prev) => [
        ...prev,
        { id: Date.now(), type: 'system', text: `\n[✓ Exported to: ${result.filePath}]` },
      ]);
    }
  }, [outputLines, scanText, analysisLines]);

  // ── IDS/IPS risk — active when evasion/spoofing/paranoid-timing flags are on ─
  const IDS_FLAG_IDS = new Set([
    'fragment', 'mtu', 'decoy', 'spoof_ip', 'spoof_mac',
    'data_length', 'badsum', 'idle_scan', 'ftp_bounce',
    'sn_null', 'sf', 'sx',
  ]);
  const hasIdsRisk =
    Object.keys(flagSelections).some((id) => IDS_FLAG_IDS.has(id)) ||
    (flagSelections.timing_template === '0' || flagSelections.timing_template === '1');

  // ── Load a follow-up command into the builder target ──────────────────────
  const handleLoadCommand = useCallback((cmd) => {
    // Extract the last non-flag token as the target
    const parts = cmd.replace(/^nmap\s+/, '').trim().split(/\s+/);
    const t = [...parts].reverse().find((p) => !p.startsWith('-'));
    if (t && t !== '<target>') { targetTouchedRef.current = true; setTarget(t); }
    setActiveTab('builder');
  }, []);

  // Doplni do buildera -sV + vuln skripty (z panela VULNERABILITIES & FIXES).
  const handleLoadVulnScan = useCallback(() => {
    setFlagSelections((prev) => ({
      ...prev,
      sv: true,
      script: [removeScripts(prev.script, ['vuln', 'vulners']), 'vuln', 'vulners'].filter(Boolean).join(','),
    }));
    if (scannedTarget) { targetTouchedRef.current = true; setTarget(scannedTarget); }
    setActiveTab('builder');
  }, [scannedTarget]);

  // ── Validation for run button ─────────────────────────────────────────────
  const targetValid = target.trim() && validateTarget(target).valid;
  const canRun =
    nmapStatus.available &&
    targetValid &&
    scanStatus !== 'scanning';

  // ── Klavesove skratky (handlery cez ref, listener sa registruje raz) ──────
  const shortcutRef = useRef({});
  shortcutRef.current = {
    run: () => { if (canRun) handleRunScan(); },
    kill: () => { if (scanStatus === 'scanning') handleKillScan(); },
    copy: handleCopy,
    search: () => {
      setActiveTab('builder');
      setTimeout(() => document.querySelector('.builder-search .search-input')?.focus(), 0);
    },
    tab: (t) => setActiveTab(t),
  };
  useEffect(() => {
    const onKey = (e) => {
      const m = matchShortcut(e, IS_MAC);
      if (!m || document.querySelector('.modal-backdrop')) return; // dialog ma vlastne klavesy
      e.preventDefault();
      shortcutRef.current[m.action]?.(m.tab);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // ── Kontrola novej verzie pri spusteni (max. raz za 12 h, da sa vypnut) ───
  useEffect(() => {
    if (!window.electronAPI?.checkUpdate) return undefined;
    const prefs = loadUpdatePrefs();
    if (!shouldAutoCheck(prefs)) return undefined;
    const timer = setTimeout(async () => {
      const r = await window.electronAPI.checkUpdate();
      if (r && r.ok) saveUpdatePrefs({ ...loadUpdatePrefs(), lastCheck: Date.now() });
      if (shouldShowBanner(r, loadUpdatePrefs())) setUpdate(r);
    }, 4000);
    return () => clearTimeout(timer);
  }, []);

  const dismissUpdate = useCallback((disableAuto = false) => {
    const prefs = loadUpdatePrefs();
    saveUpdatePrefs({ ...prefs, dismissed: update?.latest || prefs.dismissed, ...(disableAuto ? { auto: false } : {}) });
    setUpdate(null);
  }, [update]);

  // ── Status indicator label ────────────────────────────────────────────────
  const statusMap = {
    idle: { label: t('READY'), cls: 'status--ready' },
    scanning: { label: t('SCANNING'), cls: 'status--scanning' },
    done: { label: t('DONE'), cls: 'status--done' },
    error: { label: t('ERROR'), cls: 'status--error' },
    killed: { label: t('KILLED'), cls: 'status--killed' },
  };
  const currentStatus = statusMap[scanStatus] || statusMap.idle;

  // ── No Electron API guard ─────────────────────────────────────────────────
  if (!window.electronAPI) {
    return (
      <div className="no-electron">
        <div className="no-electron__box">
          <div className="no-electron__icon">⚠</div>
          <h2>{t('Electron API not available')}</h2>
          <p>{t('This app must be run as an Electron desktop application.')}</p>
          <code>npm run dev</code>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      {/* ── Header ────────────────────────────────────────────────────────── */}
      <header className="app-header">
        <div className="app-header__left">
          <span className={`status-dot ${currentStatus.cls}`} />
          <span className={`status-label ${currentStatus.cls}`}>{currentStatus.label}</span>
        </div>
        <div className="app-header__center">
          <span className="app-title">NMAP COMMAND BUILDER</span>
        </div>
        <div className="app-header__right">
          <div className="lang-switch" role="group" aria-label={t('Language')}>
            {['en', 'sk'].map((l) => (
              <button key={l} className={`lang-switch__btn ${lang === l ? 'lang-switch__btn--active' : ''}`}
                onClick={() => setLang(l)} aria-pressed={lang === l} title={l === 'sk' ? 'Slovenčina' : 'English'}>
                {l.toUpperCase()}
              </button>
            ))}
          </div>
          {nmapStatus.checked && (
            <span className={`nmap-version ${nmapStatus.available ? 'nmap-version--ok' : 'nmap-version--err'}`}>
              {nmapStatus.available ? `● ${nmapStatus.version}` : `✗ ${t('nmap not found')}`}
            </span>
          )}
        </div>
      </header>

      {update && (
        <UpdateBanner
          update={update}
          onDownload={(url) => window.electronAPI.openDownload(url)}
          onLater={() => dismissUpdate(false)}
          onDisableAuto={() => dismissUpdate(true)}
        />
      )}

      {/* ── nmap not found warning ────────────────────────────────────────── */}
      {nmapStatus.checked && !nmapStatus.available && (
        <div className="nmap-warn-bar">
          ⚠ {t('nmap is not installed or not in PATH.')}
          {' '}{t('Install:')} <code>sudo apt install nmap</code> (Linux) · <code>brew install nmap</code> (macOS)
        </div>
      )}

      {/* ── Windows: Npcap chýba (potrebný pre SYN / OS / UDP skeny) ─────── */}
      {nmapStatus.npcapMissing && (
        <div className="nmap-warn-bar nmap-warn-bar--npcap">
          ⚠ {t('Npcap is required for privileged scans on Windows.')}
          {nmapStatus.npcapInstallerBundled && (
            <button className="btn btn--xs noroot-notice__btn" style={{ marginLeft: 10 }}
              onClick={async () => {
                await window.electronAPI.installNpcap();
              }}>
              {t('Install Npcap')}
            </button>
          )}
        </div>
      )}

      {/* ── Command Preview Bar ───────────────────────────────────────────── */}
      <CommandPreview
        command={command}
        warnings={warnings}
        requiresRoot={requiresRoot}
        hasTarget={hasTarget}
        isAdvanced={advancedMode}
        hasIdsRisk={hasIdsRisk}
        copied={copied}
        onCopy={handleCopy}
        onClear={handleClear}
      />

      {/* ── Main Body ─────────────────────────────────────────────────────── */}
      <div className="app-body">
        {/* LEFT: Tab nav + tab content */}
        <div className="left-panel">
          {/* Tab navigation */}
          <div className="tab-nav">
            <button
              className={`tab-btn ${activeTab === 'builder' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('builder')}
            >
              {t('BUILDER')}
            </button>
            <button
              className={`tab-btn ${activeTab === 'cheatsheet' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('cheatsheet')}
            >
              {t('CHEATSHEET')}
            </button>
            <button
              className={`tab-btn ${activeTab === 'presets' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('presets')}
            >
              {t('PRESETS')}
            </button>
            <button
              className={`tab-btn ${activeTab === 'scripts' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('scripts')}
              title={t('NSE script library')}
            >
              {t('SCRIPTS')}
            </button>
            <button
              className={`tab-btn tab-btn--ethics ${activeTab === 'ethics' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('ethics')}
              title={t('Legal notice, ethical usage guide, root-required scans')}
            >
              {t('ETHICS')}
            </button>
            <button
              className={`tab-btn ${activeTab === 'tools' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('tools')}
              title={t('Network tools: WHOIS, DNS, SSL, IP info')}
            >
              {t('TOOLS')}
            </button>

            {/* Safe / Advanced toggle */}
            <div className="mode-toggle">
              <button
                className={`mode-btn ${!advancedMode ? 'mode-btn--active' : ''}`}
                onClick={() => setAdvancedMode(false)}
                title={t('Safe mode — standard flags only')}
              >
                {t('SAFE')}
              </button>
              <button
                className={`mode-btn mode-btn--adv ${advancedMode ? 'mode-btn--active' : ''}`}
                onClick={() => setAdvancedMode(true)}
                title={t('Advanced mode — enable evasion and spoofing flags')}
              >
                {t('ADV')}
              </button>
            </div>
          </div>

          {/* Tab content */}
          <div className="tab-content">
            {activeTab === 'builder' && (
              <BuilderTab
                target={target}
                onTargetChange={handleTargetChange}
                networks={networks}
                onUseNetwork={handleUseNetwork}
                onRefreshNetworks={refreshNetworks}
                flagSelections={flagSelections}
                onFlagChange={handleFlagChange}
                advancedMode={advancedMode}
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
                expandedCategories={expandedCategories}
                onToggleCategory={handleToggleCategory}
              />
            )}
            {activeTab === 'cheatsheet' && (
              <CheatsheetTab />
            )}
            {activeTab === 'presets' && (
              <PresetsTab
                onLoadPreset={handleLoadPreset}
                advancedMode={advancedMode}
                userPresets={userPresets}
                canSave={Object.values(flagSelections).some((v) => v !== false && v !== '' && v != null)}
                currentTarget={target.trim()}
                onSaveUserPreset={handleSaveUserPreset}
                onDeleteUserPreset={handleDeleteUserPreset}
                onExportPresets={handleExportPresets}
                onImportPresets={handleImportPresets}
              />
            )}
            {activeTab === 'scripts' && (
              <ScriptsTab
                scriptValue={flagSelections.script}
                scriptArgsValue={flagSelections.script_args}
                advancedMode={advancedMode}
                onToggleScript={handleToggleScript}
                onAddScriptArg={handleAddScriptArg}
                onRemoveScripts={handleRemoveScripts}
                onClearScripts={handleClearScripts}
              />
            )}
            {activeTab === 'ethics' && (
              <EthicsTab />
            )}
            {activeTab === 'tools' && (
              <ToolsTab />
            )}
          </div>
        </div>

        {/* RIGHT: Scan controls + terminal + results + history */}
        <div className="right-panel">
          {/* Scan control buttons */}
          <div className="scan-controls">
            <button
              className="btn btn--run"
              onClick={handleRunScan}
              disabled={!canRun}
              title={
                !nmapStatus.available
                  ? t('nmap not found')
                  : !targetValid
                  ? t('Enter a valid target first')
                  : scanStatus === 'scanning'
                  ? t('Scan already running')
                  : t('Run nmap scan ({keys})', { keys: IS_MAC ? '⌘↵' : 'Ctrl+Enter' })
              }
            >
              {scanStatus === 'scanning' ? (
                <>
                  <span className="btn-spinner" /> {t('SCANNING…')}
                </>
              ) : (
                `▶ ${t('RUN SCAN')}`
              )}
            </button>

            <button
              className="btn btn--kill"
              onClick={handleKillScan}
              disabled={scanStatus !== 'scanning'}
              title={t('Kill running scan ({keys})', { keys: IS_MAC ? '⌘.' : 'Ctrl+.' })}
            >
              ⊗ {t('KILL')}
            </button>

            <div className="discover-group" title={discoveryTarget ? t('Find all active devices in {net}', { net: discoveryTarget }) : t('No network detected — enter a range (e.g. 192.168.1.0/24) as the target')}>
              <button
                className="btn btn--discover"
                onClick={() => handleDiscoverNetwork(discoverMode)}
                disabled={!nmapStatus.available || !discoveryTarget || scanStatus === 'scanning'}
              >
                ⌖ {t('SCAN NETWORK')}
              </button>
              <select
                className="discover-mode"
                value={discoverMode}
                onChange={(e) => setDiscoverMode(e.target.value)}
                disabled={scanStatus === 'scanning'}
                aria-label={t('Network scan mode')}
              >
                <option value="quick">{t('quick · devices only (~1–2 min)')}</option>
                <option value="standard">{t('detailed · ports + services (minutes)')}</option>
              </select>
            </div>

            {requiresRoot && (
              <span className="badge badge--root" title={t('This scan requires root / sudo privileges')}>
                ⚠ {t('REQUIRES ROOT')}
              </span>
            )}
          </div>

          <MonitorBar
            monitor={monitor}
            canStart={scanStatus === 'done' && Boolean(currentSnapshot) && Boolean(lastScanRef.current) && !lastScanRef.current.elevated}
            lastTarget={lastScanRef.current?.target || ''}
            scanning={scanStatus === 'scanning'}
            onStart={handleStartMonitor}
            onStop={handleStopMonitor}
            onRunNow={handleMonitorNow}
            reportDir={reportDir}
            onChooseReportDir={handleChooseReportDir}
          />

          {rootNeeds.length > 0 && (
            <div className="noroot-notice">
              <div className="noroot-notice__title">
                ⚠ {t('THIS SCAN NEEDS ROOT — the app is running without root')}
              </div>
              {rootNeeds.map((r) => (
                <div key={r.id} className={`noroot-notice__row noroot-notice__row--${r.effect}`}>
                  <code>{r.flag}</code>
                  <span className="noroot-notice__effect">
                    {r.effect === 'quits' ? t('nmap will stop') : t('ignored by nmap')}
                  </span>
                  {r.tip && <span className="noroot-notice__note">{t('tip:')} {t(r.tip)}</span>}
                </div>
              ))}
              {nmapStatus.canElevate ? (
                <div className="noroot-notice__elevate">
                  <button
                    className="btn btn--xs noroot-notice__btn"
                    onClick={handleRunElevated}
                    disabled={scanStatus === 'scanning' || elevateBlocked.length > 0}
                  >
                    🔒 {t('RUN AS ADMINISTRATOR')}
                  </button>
                  <span className="noroot-notice__how">
                    {elevateBlocked.length > 0
                      ? t('Not possible with {flags} — as administrator nmap must not read or write files. Remove them first.', { flags: elevateBlocked.join(' ') })
                      : t('The same command runs with administrator rights. The system asks for your password — the app never sees or stores it.')}
                  </span>
                </div>
              ) : (
                <div className="noroot-notice__how">
                  {t('Start the app with')} <code>sudo</code> {t('(see README → Root Privileges).')}
                </div>
              )}
            </div>
          )}

          {/* Terminal */}
          <TerminalOutput
            lines={outputLines}
            scanStatus={scanStatus}
            onExport={handleExport}
            onClear={() => {
              resetFullOutput();
              setOutputLines([]);
              setCurrentSnapshot(null);
              setScanStatus('idle');
              setScannedTarget('');
            }}
          />

          {/* Results panels — shown after scan completes (spolocne rolovanie) */}
          <div className="results-area">
          {inventory && (
            <InventoryPanel
              devices={inventory}
              target={scannedTarget}
              onScanDevice={handleScanDevice}
              // Bez rootu macOS / Linux MAC adresy casto neda → rychle prehladanie ako spravca (ARP)
              onFindMacs={nmapStatus.canElevate && scanStatus !== 'scanning' ? () => handleDiscoverNetwork('quick', { elevated: true }) : undefined}
              onExportCsv={() => window.electronAPI.exportResult(
                inventoryCsv(inventory, deviceLabels), `network-devices-${Date.now()}.csv`, [{ name: 'CSV', extensions: ['csv'] }]
              )}
              labels={deviceLabels}
              onLabelChange={handleLabelChange}
            />
          )}
          {inventory && (
            <NetworkMap
              devices={inventory}
              findings={findings}
              gatewayIp={gateway}
              localIps={localIps}
              target={scannedTarget}
              onScanDevice={handleScanDevice}
              labels={deviceLabels}
            />
          )}
          <DiffPanel
            current={currentSnapshot}
            snapshots={snapshots}
            baselineId={comparison?.baseline.id ?? null}
            onBaselineChange={setDiffBaselineId}
            onClearSaved={handleClearSnapshots}
          />
          <PortsPanel
            lines={analysisLines}
            scanStatus={scanStatus}
            onLoadCommand={handleLoadCommand}
          />
          <HostInfoPanel lines={analysisLines} scanStatus={scanStatus} />
          <FindingsPanel
            lines={analysisLines}
            scanStatus={scanStatus}
            onLoadVulnScan={handleLoadVulnScan}
            onExport={handleExport}
            findings={findings}
            intel={rawFindings.some((f) => f.cves?.length) ? {
              enabled: intelEnabled, loading: intelLoading, meta: intelData?.meta, nvdDone: nvdProgress.done, nvdTotal: nvdProgress.total,
            } : null}
            onToggleIntel={handleToggleIntel}
          />
          <IntelPanel lines={analysisLines} scanStatus={scanStatus} />
          <FollowUpPanel
            lines={analysisLines}
            scanStatus={scanStatus}
            scannedTarget={scannedTarget}
            onLoadCommand={handleLoadCommand}
          />
          </div>

          {/* History */}
          <ScanHistory history={scanHistory} onLoad={handleLoadFromHistory} />
        </div>
      </div>

      {/* ── Footer ────────────────────────────────────────────────────────── */}
      {reportDialog && (
        <ReportDialog
          format={reportDialog}
          initial={reportMeta.saved ? reportMeta : { ...reportMeta, lang }}
          onCancel={() => setReportDialog(null)}
          onGenerate={(meta) => {
            saveReportMeta(meta);
            setReportMeta({ ...meta, saved: true });
            setReportDialog(null);
            handleExport(reportDialog, meta);
          }}
        />
      )}

      <footer className="app-footer">
        <span className="app-footer__text">
          {t('Created by')} <span className="app-footer__author">Peter Obala</span>
        </span>
        <span className="app-footer__sep">·</span>
        <span className="app-footer__item">Nmap Command Builder v1.9.0</span>
        <span className="app-footer__sep">·</span>
        <span className="app-footer__item">{t('Use responsibly & ethically')}</span>
        <span className="app-footer__sep app-footer__keys-sep">·</span>
        <span className="app-footer__keys" title={t('Keyboard shortcuts')}>
          {shortcutHints(IS_MAC).map((h) => (
            <span key={h.label}><kbd>{h.keys}</kbd> {t(h.label)}</span>
          ))}
        </span>
      </footer>
    </div>
  );
}
