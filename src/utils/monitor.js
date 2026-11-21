// ─── Monitorovanie: pravidelne opakovanie skenu + upozornenie na zmeny ────────
// Bezi len ked je aplikacia otvorena. Nastavenie sa uklada lokalne, takze
// po opatovnom spusteni aplikacie monitorovanie pokracuje.

const STORE_KEY = 'ncb.monitor.v1';
export const MONITOR_INTERVALS = [15, 60, 360, 1440]; // minuty

function defaultStorage() {
  try { return window.localStorage; } catch (_) { return null; }
}

const RESULTS = ['', 'first', 'nochange', 'changes', 'nohosts', 'error'];
const COUNT_KEYS = ['findings', 'ports', 'hosts', 'fixed', 'closed'];
const normCounts = (c) => Object.fromEntries(COUNT_KEYS.map((k) => [k, c && Number.isInteger(c[k]) && c[k] >= 0 ? c[k] : 0]));

const isStrArray = (a) => Array.isArray(a) && a.length > 0 && a.length <= 200 && a.every((x) => typeof x === 'string' && x.length <= 2000);

/** Platna konfiguracia alebo null. */
export function normalizeMonitor(m) {
  if (!m || typeof m !== 'object') return null;
  if (!isStrArray(m.args) || typeof m.command !== 'string' || typeof m.target !== 'string' || !m.target.trim()) return null;
  const interval = MONITOR_INTERVALS.includes(Number(m.intervalMin)) ? Number(m.intervalMin) : 60;
  const num = (v) => (Number.isFinite(v) && v > 0 ? v : null);
  return {
    args: m.args, command: m.command.slice(0, 4000), target: m.target.trim().slice(0, 500),
    intervalMin: interval,
    lastRun: num(m.lastRun),
    nextRun: num(m.nextRun),
    runs: Number.isInteger(m.runs) && m.runs >= 0 ? m.runs : 0,
    lastResult: RESULTS.includes(m.lastResult) ? m.lastResult : '',
    lastCounts: normCounts(m.lastCounts),
    alerts: Number.isInteger(m.alerts) && m.alerts >= 0 ? m.alerts : 0,
  };
}

export function loadMonitor(storage = defaultStorage()) {
  try { return normalizeMonitor(JSON.parse(storage.getItem(STORE_KEY) || 'null')); } catch (_) { return null; }
}

export function saveMonitor(m, storage = defaultStorage()) {
  try {
    if (m) storage.setItem(STORE_KEY, JSON.stringify(m)); else storage.removeItem(STORE_KEY);
  } catch (_) { /* ignore */ }
  return m;
}

/** Novy monitor pre prave dokonceny sken; prvy opakovany beh o `intervalMin`. */
export function startMonitor({ args, command, target, intervalMin }, now = Date.now()) {
  return normalizeMonitor({ args, command, target, intervalMin, lastRun: now, nextRun: now + intervalMin * 60000, runs: 0 });
}

/** Je cas na dalsi beh? (sken nesmie prave bezat) */
export function monitorDue(m, now = Date.now(), scanning = false) {
  return Boolean(m && !scanning && m.nextRun && now >= m.nextRun);
}

/** Po spusteni behu: posun dalsieho terminu (aj ked pocitac spal — bez dobiehania). */
export function markRun(m, now = Date.now()) {
  return { ...m, lastRun: now, nextRun: now + m.intervalMin * 60000, runs: m.runs + 1 };
}

/**
 * Zmeny, na ktore treba upozornit (nove zranitelnosti, porty, zariadenia).
 * @returns {{ alert: boolean, counts: { findings, ports, hosts, fixed, closed } }}
 */
export function monitorChanges(diff) {
  if (!diff) return { alert: false, counts: { findings: 0, ports: 0, hosts: 0, fixed: 0, closed: 0 } };
  const counts = {
    findings: diff.newFindings.length,
    ports: diff.openedPorts.length,
    hosts: diff.newHosts.length,
    fixed: diff.resolvedFindings.length,
    closed: diff.closedPorts.length,
  };
  return { alert: counts.findings + counts.ports + counts.hosts > 0, counts };
}
