import { FINDING_RULES, GENERIC_VULN_FIX, CVE_FIX } from '../data/remediation';

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const RE_HOST = /^Nmap scan report for (.+)$/;
const RE_NSE_ERROR = /^\|[_ ]\s*(ERROR|NSE):\s*(.+)$/i;
const RE_PORT = /^(\d+)\/(tcp|udp)\s+\S+/;
// Hlavicka skriptu: "| ftp-anon: ..." alebo "|_http-title: ..." (presne 1 znak za "|").
// Vnorene riadky maju za "|" aspon 2 medzery.
const RE_SCRIPT_HEAD = /^\|[_ ]([a-z0-9][\w.-]*):(.*)$/i;
const RE_VULNERS_ROW = /\b(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)\b/;

function cvssSeverity(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Rozdeli surovy vystup nmapu na bloky NSE skriptov s kontextom host/port.
 * @returns {Array<{ script, host, port, lines: string[] }>}
 */
export function splitScriptBlocks(text) {
  const blocks = [];
  let host = '';
  let port = null;
  let current = null;

  for (const raw of String(text || '').split('\n')) {
    const line = raw.replace(/\r$/, '');

    const h = line.match(RE_HOST);
    if (h) { host = h[1].trim(); port = null; current = null; continue; }

    if (/^Host script results:/.test(line)) { port = null; current = null; continue; }

    const p = line.match(RE_PORT);
    if (p) { port = `${p[1]}/${p[2]}`; current = null; continue; }

    if (!line.startsWith('|')) { current = null; continue; }

    const head = line.match(RE_SCRIPT_HEAD);
    if (head) {
      current = { script: head[1], host, port, lines: [line] };
      blocks.push(current);
    } else if (current) {
      current.lines.push(line);
    }
  }
  return blocks;
}

const MAX_CVES = 50;

/** Vsetky CVE v texte bloku (bez duplicit), bez skore. */
function cvesIn(body) {
  return [...new Set(body.match(/CVE-\d{4}-\d{4,7}/g) || [])].slice(0, MAX_CVES).map((id) => ({ id, score: null }));
}

function vulnTitle(lines) {
  // Riadok za "VULNERABLE:" obsahuje nazov zranitelnosti.
  const i = lines.findIndex((l) => /VULNERABLE:\s*$/.test(l));
  if (i >= 0 && lines[i + 1]) return lines[i + 1].replace(/^\|_?\s*/, '').trim();
  return '';
}

/**
 * Najde zranitelnosti / nebezpecne konfiguracie vo vystupe NSE skriptov
 * a priradi k nim kroky na opravu.
 */
export function parseFindings(text) {
  const findings = [];
  const seen = new Set();

  const add = (f) => {
    const key = `${f.id}|${f.host}|${f.port || ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  for (const b of splitScriptBlocks(text)) {
    const body = b.lines.join('\n');
    const vulnerable = /State: VULNERABLE/.test(body);
    const likelyVulnerable = /State: LIKELY VULNERABLE/.test(body);
    const ctx = { host: b.host, port: b.port, script: b.script };
    let matched = false;

    // vulners: zoznam CVE so skore CVSS — overenie na zaklade verzie, nie ziveho testu
    if (b.script === 'vulners') {
      const cves = [];
      for (const l of b.lines) {
        const m = l.match(RE_VULNERS_ROW);
        if (m && !cves.some((c) => c.id === m[1])) cves.push({ id: m[1], score: parseFloat(m[2]) });
      }
      if (cves.length > 0) {
        cves.sort((a, c) => c.score - a.score);
        const max = cves[0].score;
        add({
          ...ctx,
          id: 'vulners',
          title: `${cves.length} known CVE${cves.length > 1 ? 's' : ''} for this service version (max CVSS ${max})`,
          severity: cvssSeverity(max),
          verificationStatus: 'VERSION_MATCH',
          fix: CVE_FIX,
          evidence: cves.slice(0, 5).map((c) => `${c.id} (${c.score})`).join(', '),
          refs: cves.slice(0, 3).map((c) => `https://nvd.nist.gov/vuln/detail/${c.id}`),
          cves: cves.slice(0, MAX_CVES),
        });
      }
      continue;
    }

    for (const rule of FINDING_RULES) {
      if (rule.requireVulnerable && !vulnerable && !likelyVulnerable) continue;
      if (!rule.match.test(body)) continue;
      matched = true;
      add({
        ...ctx,
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        verificationStatus: rule.requireVulnerable
          ? (likelyVulnerable && !vulnerable ? 'LIKELY' : 'CONFIRMED')
          : 'DETECTED',
        fix: rule.fix,
        evidence: rule.requireVulnerable
          ? [vulnTitle(b.lines), (body.match(/CVE-\d{4}-\d{4,}/) || [])[0]].filter(Boolean).join(' — ')
          : b.lines.find((l) => rule.match.test(l))?.replace(/^\|_?\s*/, '').replace(/^[\w.-]+:\s*/, '').trim() || '',
        refs: rule.refs || [],
        cves: cvesIn(body),
      });
    }

    if ((vulnerable || likelyVulnerable) && !matched) {
      const cve = body.match(/CVE-\d{4}-\d{4,}/);
      add({
        ...ctx,
        id: `generic:${b.script}`,
        title: vulnTitle(b.lines) || `${b.script}: vulnerable`,
        severity: 'high',
        verificationStatus: likelyVulnerable && !vulnerable ? 'LIKELY' : 'CONFIRMED',
        fix: GENERIC_VULN_FIX,
        evidence: cve ? cve[0] : '',
        refs: cve ? [`https://nvd.nist.gov/vuln/detail/${cve[0]}`] : [],
        cves: cvesIn(body),
      });
    }
  }

  return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

/**
 * Zachytí chyby NSE skriptov z výstupu nmapu.
 * Vracia { host, port, script, error }[] — informačné záznamy, neovplyvňujú počet nálezov.
 */
export function parseNseErrors(text) {
  const errors = [];
  let host = '';
  let port = null;
  let script = null;
  for (const raw of String(text || '').split('\n')) {
    const line = raw.replace(/\r$/, '');
    const h = line.match(RE_HOST);
    if (h) { host = h[1].trim(); port = null; script = null; continue; }
    if (/^Host script results:/.test(line)) { port = null; script = null; continue; }
    const p = line.match(RE_PORT);
    if (p) { port = `${p[1]}/${p[2]}`; script = null; continue; }
    const err = line.match(RE_NSE_ERROR);
    if (err) {
      errors.push({ host, port, script, error: err[2].trim() });
      continue;
    }
    const head = line.match(RE_SCRIPT_HEAD);
    if (head) { script = head[1]; continue; }
  }
  return errors;
}
