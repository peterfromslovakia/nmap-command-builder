// ─── Vlastné menovky zariadení ────────────────────────────────────────────────
// Uložené v localStorage podľa MAC adresy (primárny kľúč) alebo IP (záložný).
// setLabel vracia nový objekt (immutable) — ukladanie robí volajúci cez saveLabels.

const STORE_KEY = 'ncb.deviceLabels.v1';

export function loadLabels() {
  try {
    const raw = typeof window !== 'undefined' && window.localStorage && window.localStorage.getItem(STORE_KEY);
    if (!raw) return { byMac: {}, byIp: {} };
    const v = JSON.parse(raw);
    return {
      byMac: (v && typeof v.byMac === 'object' && !Array.isArray(v.byMac)) ? v.byMac : {},
      byIp:  (v && typeof v.byIp  === 'object' && !Array.isArray(v.byIp))  ? v.byIp  : {},
    };
  } catch (_) {
    return { byMac: {}, byIp: {} };
  }
}

export function saveLabels(labels) {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(STORE_KEY, JSON.stringify(labels));
    }
  } catch (_) { /* ignore quota / private window */ }
}

/** Vráti menovku zariadenia. MAC má prednosť pred IP. */
export function getLabel(mac, ip, labels) {
  if (!labels) return '';
  if (mac && labels.byMac && labels.byMac[mac]) return labels.byMac[mac];
  if (ip  && labels.byIp  && labels.byIp[ip])   return labels.byIp[ip];
  return '';
}

/**
 * Vráti nový objekt labels s nastavenou menovkou.
 * Prázdny name záznam vymaže. MAC má prednosť; ak chýba, uloží podľa IP.
 */
export function setLabel(mac, ip, name, labels) {
  const base = labels || { byMac: {}, byIp: {} };
  const byMac = { ...base.byMac };
  const byIp  = { ...base.byIp };

  if (mac) {
    if (name) byMac[mac] = name; else delete byMac[mac];
    // Ak existoval starý záznam podľa IP pre toto zariadenie, ponechaj ho
  } else if (ip) {
    if (name) byIp[ip] = name; else delete byIp[ip];
  }
  return { byMac, byIp };
}
