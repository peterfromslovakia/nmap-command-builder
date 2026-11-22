import { parseHosts } from './report';
import { parseFindings } from './findings';
import { detectScanType, arePortsComparable, areVulnsComparable, getPortSpec } from './scanMeta';

// ─── Snimka vysledkov skenu (kompaktna, bez surovego vystupu) ──────────────────

export function makeSnapshot({ id, time, target, command, text, exitCode, signal }) {
  return {
    id,
    time,
    target: String(target || '').trim(),
    command,
    // scanType + portSpec umožňujú diff-u rozlíšiť nekompatibilné metodiky
    scanType: detectScanType(command),
    portSpec: getPortSpec(command),
    exitCode: exitCode != null ? exitCode : undefined,
    signal: signal || undefined,
    hosts: parseHosts(text).map((h) => ({
      host: h.host,
      ports: h.ports.map(({ port, proto, service, version }) => ({ port, proto, service, version })),
    })),
    findings: parseFindings(text).map(({ id: fid, title, severity, host, port }) => ({
      id: fid, title, severity, host, port: port || '',
    })),
  };
}

// "fileserver.lan (192.168.1.20)" → "192.168.1.20"; hostname sa moze zmenit, IP je stabilnejsia.
export function hostKey(host) {
  const m = String(host).match(/\(([^()]+)\)\s*$/);
  return (m ? m[1] : String(host)).trim();
}

const portKey = (p) => `${p.port}/${p.proto}`;
const findingKey = (f) => `${f.id}|${hostKey(f.host)}|${f.port}`;

/**
 * Porovna dve snimky (prev = starsi, curr = novsi).
 *
 * Rozlišuje metodiku skenov: ak aktuálny sken nepoužíval rovnakú metodiku,
 * neoznačíme netestované veci ako "zatvorené" alebo "opravené".
 */
export function diffScans(prev, curr) {
  const prevHosts = new Map(prev.hosts.map((h) => [hostKey(h.host), h]));
  const currHosts = new Map(curr.hosts.map((h) => [hostKey(h.host), h]));

  const newHosts = curr.hosts.filter((h) => !prevHosts.has(hostKey(h.host)));
  const goneHosts = prev.hosts.filter((h) => !currHosts.has(hostKey(h.host)));

  // Ak sken netestoval porty (napr. -sn), nesmieme označiť predošlé porty
  // ako "zatvorené" — jednoducho neboli testované.
  const portsComparable = arePortsComparable(prev.command, curr.command);
  const vulnsComparable = areVulnsComparable(prev.command, curr.command);

  const openedPorts = [];
  const closedPorts = [];
  const changedVersions = [];

  if (portsComparable) {
    for (const [key, ch] of currHosts) {
      const ph = prevHosts.get(key);
      if (!ph) continue; // novy host — jeho porty su v newHosts
      const pp = new Map(ph.ports.map((p) => [portKey(p), p]));
      const cp = new Map(ch.ports.map((p) => [portKey(p), p]));
      for (const [k, p] of cp) {
        const before = pp.get(k);
        if (!before) openedPorts.push({ host: ch.host, ...p });
        else if (before.version && p.version && before.version !== p.version) {
          changedVersions.push({ host: ch.host, port: p.port, proto: p.proto, service: p.service, from: before.version, to: p.version });
        }
      }
      for (const [k, p] of pp) if (!cp.has(k)) closedPorts.push({ host: ch.host, ...p });
    }
  }

  const prevF = new Map(prev.findings.map((f) => [findingKey(f), f]));
  const currF = new Map(curr.findings.map((f) => [findingKey(f), f]));
  const newFindings = curr.findings.filter((f) => !prevF.has(findingKey(f)));
  // Vyriešený = nález zmizol, ale host je stále v skene — LEN ak oba skeny
  // spúšťali rovnaké typy vulnerability skriptov.
  const resolvedFindings = vulnsComparable
    ? prev.findings.filter((f) => !currF.has(findingKey(f)) && currHosts.has(hostKey(f.host)))
    : [];

  const total = newHosts.length + goneHosts.length + openedPorts.length + closedPorts.length +
    changedVersions.length + newFindings.length + resolvedFindings.length;

  // portRangeDiffers: skenovaný rozsah portov sa líšil — "zatvorené porty" môžu byť
  // netestované, nie skutočne zatvorené. Upozornenie, nie blokovanie diff-u.
  const portRangeDiffers = portsComparable && (prev.portSpec || 'default') !== (curr.portSpec || 'default');

  // methodDiffers: informuje UI, že porovnanie portov alebo nálezov nie je spoľahlivé
  // (napr. jeden sken bol discovery-only, druhý mal vuln skripty; alebo iný rozsah portov)
  const methodDiffers = !portsComparable || !vulnsComparable || portRangeDiffers;

  return {
    newHosts, goneHosts, openedPorts, closedPorts, changedVersions, newFindings, resolvedFindings,
    total,
    sameCommand: normalizeCommand(prev.command) === normalizeCommand(curr.command),
    methodDiffers,
    portsComparable,
    vulnsComparable,
    portRangeDiffers,
  };
}

const normalizeCommand = (c) => String(c || '').trim().replace(/\s+/g, ' ');

// ─── Lokalne ulozenie snimok ──────────────────────────────────────────────────
// Ulozene len v tejto aplikacii (localStorage); do siete sa nic neposiela.

const STORE_KEY = 'ncb.snapshots.v1';
export const MAX_SNAPSHOTS = 30;

// Pristup k localStorage moze sam vyhodit vynimku (zakazane ulozisko).
function defaultStorage() {
  try { return window.localStorage; } catch (_) { return null; }
}

export function loadSnapshots(storage = defaultStorage()) {
  try {
    const data = JSON.parse(storage.getItem(STORE_KEY) || '[]');
    return Array.isArray(data) ? data : [];
  } catch (_) {
    return [];
  }
}

export function saveSnapshot(snapshot, storage = defaultStorage()) {
  const list = [snapshot, ...loadSnapshots(storage).filter((s) => s.id !== snapshot.id)].slice(0, MAX_SNAPSHOTS);
  try { storage.setItem(STORE_KEY, JSON.stringify(list)); } catch (_) { /* plne / zakazane ulozisko */ }
  return list;
}

export function clearSnapshots(storage = defaultStorage()) {
  try { storage.removeItem(STORE_KEY); } catch (_) { /* ignore */ }
  return [];
}

/** Starsie snimky toho isteho targetu (najnovsia prva). */
export function baselinesFor(snapshots, current) {
  return snapshots.filter((s) => s.id !== current.id && s.target === current.target && s.time < current.time);
}

/** Zvolena (alebo najnovsia) zakladna snimka pre aktualny sken + rozdiel; null ak nie je s cim porovnat. */
export function comparisonFor(snapshots, current, baselineId = null) {
  if (!current) return null;
  const list = baselinesFor(snapshots, current);
  const baseline = list.find((b) => b.id === baselineId) || list[0];
  return baseline ? { baseline, diff: diffScans(baseline, current) } : null;
}
