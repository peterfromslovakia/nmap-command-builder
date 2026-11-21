import { SEVERITY_ORDER } from './findings';

// ─── Spojenie nalezov s aktualnymi informaciami o zranitelnostiach ────────────

/** Vsetky CVE z nalezov (bez duplicit). */
export function collectCves(findings) {
  return [...new Set(findings.flatMap((f) => (f.cves || []).map((c) => c.id)))];
}

const SEV_FROM_SCORE = (s) => (s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : 'low');

/**
 * Doplni k nalezom KEV / EPSS / NVD:
 *  - cveDetails: [{ id, score, kev, epss, nvd }] zoradene podla zavaznosti
 *  - exploited: aspon jedno CVE je v CISA KEV (aktivne zneuzivane)
 *  - aktivne zneuzivany nalez ma zavaznost aspon "high" (escalated: true)
 *  - zoradenie: zavaznost → zneuzivane → EPSS
 */
export function applyIntel(findings, intel) {
  const kev = (intel && intel.kev) || {};
  const epss = (intel && intel.epss) || {};
  const nvd = (intel && intel.nvd) || {};

  const out = findings.map((f) => {
    const cveDetails = (f.cves || []).map((c) => {
      const n = nvd[c.id] || null;
      return {
        id: c.id,
        score: c.score ?? (n ? n.score : null),
        kev: kev[c.id] || null,
        epss: epss[c.id] ? epss[c.id].epss : null,
        percentile: epss[c.id] ? epss[c.id].percentile : null,
        nvd: n,
      };
    }).sort((a, b) => Number(Boolean(b.kev)) - Number(Boolean(a.kev)) || (b.epss ?? -1) - (a.epss ?? -1) || (b.score ?? -1) - (a.score ?? -1));

    const kevHits = cveDetails.filter((c) => c.kev);
    const exploited = kevHits.length > 0;
    const epssMax = cveDetails.reduce((m, c) => (c.epss != null && c.epss > (m ?? -1) ? c.epss : m), null);
    const nvdMax = cveDetails.reduce((m, c) => (c.nvd?.score != null && c.nvd.score > (m ?? -1) ? c.nvd.score : m), null);

    let severity = f.severity;
    let escalated = false;
    if (exploited && SEVERITY_ORDER[severity] > SEVERITY_ORDER.high) { severity = 'high'; escalated = true; }
    // Generický nalez bez skore: NVD CVSS moze zavaznost upresnit nahor.
    if (nvdMax != null && SEVERITY_ORDER[SEV_FROM_SCORE(nvdMax)] < SEVERITY_ORDER[severity] && f.id.startsWith('generic:')) {
      severity = SEV_FROM_SCORE(nvdMax);
      escalated = true;
    }

    return {
      ...f,
      severity,
      originalSeverity: f.severity,
      escalated,
      cveDetails,
      exploited,
      ransomware: kevHits.some((c) => c.kev.ransomware),
      kevDue: kevHits.map((c) => c.kev.dueDate).filter(Boolean).sort()[0] || '',
      epssMax,
    };
  });

  return out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    || Number(b.exploited) - Number(a.exploited)
    || (b.epssMax ?? -1) - (a.epssMax ?? -1));
}

/** "0.93307" → "93 %", malé hodnoty s desatinnou čiarkou. */
export function formatEpss(v) {
  if (v == null) return '';
  const pct = v * 100;
  return pct >= 10 ? `${Math.round(pct)} %` : pct >= 1 ? `${pct.toFixed(1)} %` : `${pct.toFixed(2)} %`;
}

// Zapnutie / vypnutie online informácií (lokálne nastavenie).
const STORE_KEY = 'ncb.intel.v1';
export function loadIntelEnabled() {
  try { return JSON.parse(window.localStorage.getItem(STORE_KEY) || '{}').enabled !== false; } catch (_) { return true; }
}
export function saveIntelEnabled(enabled) {
  try { window.localStorage.setItem(STORE_KEY, JSON.stringify({ enabled: Boolean(enabled) })); } catch (_) { /* ignore */ }
}
