import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import './App.css';

import { FLAG_CATEGORIES } from './data/flags';
import { buildCommand, parseScanSummary } from './utils/commandBuilder';
import { validateTarget } from './utils/validator';
import { toggleScript, removeScripts, addScriptArg } from './utils/nseSelection';
import { buildReportModel, toMarkdown, toHtml } from './utils/report';
import { rootRequirements } from './utils/privileges';

import CommandPreview from './components/CommandPreview';
import BuilderTab from './components/BuilderTab';
import CheatsheetTab from './components/CheatsheetTab';
import PresetsTab from './components/PresetsTab';
import ScriptsTab from './components/ScriptsTab';
import EthicsTab from './components/EthicsTab';
import TerminalOutput from './components/TerminalOutput';
import ScanHistory from './components/ScanHistory';
import PortsPanel from './components/PortsPanel';
import HostDiscoveryPanel from './components/HostDiscoveryPanel';
import HostInfoPanel from './components/HostInfoPanel';
import NetworkMap from './components/NetworkMap';
import FollowUpPanel from './components/FollowUpPanel';
import IntelPanel from './components/IntelPanel';
import FindingsPanel from './components/FindingsPanel';

// ─── Initial state for expanded categories ────────────────────────────────────
const initExpanded = () => {
  const s = {};
  FLAG_CATEGORIES.forEach((c) => { s[c.id] = c.safe; });
  return s;
};

const MAX_OUTPUT_CHUNKS = 5000; // strop pamate pri dlhych skenoch (-p-)

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
  const [scanHistory, setScanHistory] = useState([]);
  const [scannedTarget, setScannedTarget] = useState('');

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
      setOutputLines((prev) => {
        const next = [
          ...prev,
          { id: Date.now() + Math.random(), type: data.type, text: data.data },
        ];
        return next.length > MAX_OUTPUT_CHUNKS ? next.slice(-MAX_OUTPUT_CHUNKS) : next;
      });
    });

    const cleanDone = window.electronAPI.onScanDone((data) => {
      setScanStatus(data.signal ? 'killed' : 'done');
      const statusMsg = data.signal
        ? `\n[⊗ Scan killed — signal: ${data.signal}]`
        : `\n[✓ Scan completed — exit code: ${data.code ?? 0}]`;
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
      setScanStatus('error');
      setOutputLines((prev) => [
        ...prev,
        { id: Date.now(), type: 'error', text: `\n[✗ Scan error: ${data.message}]` },
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
    // Predvoleny target z presetu (napr. 192.168.1.0/24) len ako zaloha:
    // ak mame detegovanu siet, ostava ta (napr. 192.168.50.0/24).
    if (preset.target && networks.length === 0) {
      targetTouchedRef.current = true;
      setTarget(preset.target);
    }
    setActiveTab('builder');
  }, [networks]);

  const handleLoadFromHistory = useCallback((entry) => {
    const t = parseCommandToTarget(entry.command);
    if (t) { targetTouchedRef.current = true; setTarget(t); }
    setActiveTab('builder');
  }, []);

  const handleRunScan = useCallback(async () => {
    if (!window.electronAPI) return;
    if (scanStatus === 'scanning') return;

    const vResult = validateTarget(target);
    if (!vResult.valid) return;

    setScanStatus('scanning');
    currentCommandRef.current = command;
    setScannedTarget(target);

    const ts = new Date().toLocaleTimeString();
    setOutputLines([
      { id: Date.now(), type: 'system', text: `[${ts}] $ ${command}\n` },
      ...(rootNeeds.some((r) => r.effect === 'quits')
        ? [{ id: Date.now() + 1, type: 'error', text: `[!] Not running as root: ${rootNeeds.filter((r) => r.effect === 'quits').map((r) => r.flag).join(' ')} need root, nmap will stop. Start the app with sudo.\n` }]
        : []),
    ]);

    const res = await window.electronAPI.runScan(args);
    if (res && res.success === false) {
      setScanStatus('error');
      setOutputLines((prev) => [
        ...prev,
        { id: Date.now(), type: 'error', text: `\n[✗ Scan not started: ${res.error}]` },
      ]);
    }
  }, [scanStatus, target, command, args, rootNeeds]);

  const handleKillScan = useCallback(async () => {
    if (!window.electronAPI) return;
    setScanStatus('killed');
    await window.electronAPI.killScan();
  }, []);

  // ── Unified export handler — supports txt / json / csv ────────────────────
  const handleExport = useCallback(async (format = 'txt') => {
    if (!window.electronAPI) return;

    const rawText = outputLines.map((l) => l.text || '').join('');
    const { openPorts } = parseScanSummary(outputLines);
    const ts = new Date().toISOString();
    const stamp = Date.now();

    let content, filename, filters;

    if (format === 'md' || format === 'pdf') {
      const model = buildReportModel({
        text: rawText,
        command: currentCommandRef.current,
        target: scannedTarget || targetRef.current,
        timestamp: new Date().toLocaleString(),
        nmapVersion: nmapStatus.version,
      });
      if (format === 'pdf') {
        const res = await window.electronAPI.exportPdf(toHtml(model), `nmap-report-${stamp}.pdf`);
        setOutputLines((prev) => [
          ...prev,
          res.success
            ? { id: Date.now(), type: 'system', text: `\n[✓ PDF report saved to: ${res.filePath}]` }
            : res.cancelled ? null : { id: Date.now(), type: 'error', text: `\n[✗ PDF export failed: ${res.error}]` },
        ].filter(Boolean));
        return;
      }
      content = toMarkdown(model);
      filename = `nmap-report-${stamp}.md`;
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
  }, [outputLines, scannedTarget, nmapStatus.version]);

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

  // ── Status indicator label ────────────────────────────────────────────────
  const statusMap = {
    idle: { label: 'READY', cls: 'status--ready' },
    scanning: { label: 'SCANNING', cls: 'status--scanning' },
    done: { label: 'DONE', cls: 'status--done' },
    error: { label: 'ERROR', cls: 'status--error' },
    killed: { label: 'KILLED', cls: 'status--killed' },
  };
  const currentStatus = statusMap[scanStatus] || statusMap.idle;

  // ── No Electron API guard ─────────────────────────────────────────────────
  if (!window.electronAPI) {
    return (
      <div className="no-electron">
        <div className="no-electron__box">
          <div className="no-electron__icon">⚠</div>
          <h2>Electron API not available</h2>
          <p>This app must be run as an Electron desktop application.</p>
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
          {nmapStatus.checked && (
            <span className={`nmap-version ${nmapStatus.available ? 'nmap-version--ok' : 'nmap-version--err'}`}>
              {nmapStatus.available ? `● ${nmapStatus.version}` : '✗ nmap not found'}
            </span>
          )}
        </div>
      </header>

      {/* ── nmap not found warning ────────────────────────────────────────── */}
      {nmapStatus.checked && !nmapStatus.available && (
        <div className="nmap-warn-bar">
          ⚠ nmap is not installed or not in PATH.
          Install: <code>sudo apt install nmap</code> (Linux) · <code>brew install nmap</code> (macOS)
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
              BUILDER
            </button>
            <button
              className={`tab-btn ${activeTab === 'cheatsheet' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('cheatsheet')}
            >
              CHEATSHEET
            </button>
            <button
              className={`tab-btn ${activeTab === 'presets' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('presets')}
            >
              PRESETS
            </button>
            <button
              className={`tab-btn ${activeTab === 'scripts' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('scripts')}
              title="NSE script library"
            >
              SCRIPTS
            </button>
            <button
              className={`tab-btn tab-btn--ethics ${activeTab === 'ethics' ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab('ethics')}
              title="Legal notice, ethical usage guide, root-required scans"
            >
              ETHICS
            </button>

            {/* Safe / Advanced toggle */}
            <div className="mode-toggle">
              <button
                className={`mode-btn ${!advancedMode ? 'mode-btn--active' : ''}`}
                onClick={() => setAdvancedMode(false)}
                title="Safe mode — standard flags only"
              >
                SAFE
              </button>
              <button
                className={`mode-btn mode-btn--adv ${advancedMode ? 'mode-btn--active' : ''}`}
                onClick={() => setAdvancedMode(true)}
                title="Advanced mode — enable evasion and spoofing flags"
              >
                ADV
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
                  ? 'nmap not found'
                  : !targetValid
                  ? 'Enter a valid target first'
                  : scanStatus === 'scanning'
                  ? 'Scan already running'
                  : 'Run nmap scan'
              }
            >
              {scanStatus === 'scanning' ? (
                <>
                  <span className="btn-spinner" /> SCANNING…
                </>
              ) : (
                '▶ RUN SCAN'
              )}
            </button>

            <button
              className="btn btn--kill"
              onClick={handleKillScan}
              disabled={scanStatus !== 'scanning'}
              title="Kill running scan (SIGTERM)"
            >
              ⊗ KILL
            </button>

            {requiresRoot && (
              <span className="badge badge--root" title="This scan requires root / sudo privileges">
                ⚠ REQUIRES ROOT
              </span>
            )}
          </div>

          {rootNeeds.length > 0 && (
            <div className="noroot-notice">
              <div className="noroot-notice__title">
                ⚠ THIS SCAN NEEDS ROOT — the app is running without root
              </div>
              {rootNeeds.map((r) => (
                <div key={r.id} className={`noroot-notice__row noroot-notice__row--${r.effect}`}>
                  <code>{r.flag}</code>
                  <span className="noroot-notice__effect">
                    {r.effect === 'quits' ? 'nmap will stop' : 'ignored by nmap'}
                  </span>
                  {r.tip && <span className="noroot-notice__note">tip: {r.tip}</span>}
                </div>
              ))}
              <div className="noroot-notice__how">
                Start the app with <code>sudo</code> (see README → Root Privileges).
              </div>
            </div>
          )}

          {/* Terminal */}
          <TerminalOutput
            lines={outputLines}
            scanStatus={scanStatus}
            onExport={handleExport}
            onClear={() => {
              setOutputLines([]);
              setScanStatus('idle');
              setScannedTarget('');
            }}
          />

          {/* Results panels — shown after scan completes (spolocne rolovanie) */}
          <div className="results-area">
          <PortsPanel
            lines={outputLines}
            scanStatus={scanStatus}
            onLoadCommand={handleLoadCommand}
          />
          <HostInfoPanel lines={outputLines} scanStatus={scanStatus} />
          <HostDiscoveryPanel lines={outputLines} scanStatus={scanStatus} />
          <NetworkMap lines={outputLines} scanStatus={scanStatus} scannedTarget={scannedTarget} />
          <FindingsPanel
            lines={outputLines}
            scanStatus={scanStatus}
            onLoadVulnScan={handleLoadVulnScan}
            onExport={handleExport}
          />
          <IntelPanel lines={outputLines} scanStatus={scanStatus} />
          <FollowUpPanel
            lines={outputLines}
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
      <footer className="app-footer">
        <span className="app-footer__text">
          Created by <span className="app-footer__author">Peter Obala</span>
        </span>
        <span className="app-footer__sep">·</span>
        <span className="app-footer__item">Nmap Command Builder v1.1.0</span>
        <span className="app-footer__sep">·</span>
        <span className="app-footer__item">Use responsibly &amp; ethically</span>
      </footer>
    </div>
  );
}
