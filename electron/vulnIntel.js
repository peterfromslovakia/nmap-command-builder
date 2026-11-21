// ─── Aktualne informacie o zranitelnostiach (bez registracie a bez kluca) ─────
//
//  CISA KEV — katalog CVE, ktore utocnici realne zneuzivaju. Stiahne sa cely
//             zoznam (~2 MB), takze sa nikam neposiela ziadny udaj.
//  EPSS     — FIRST.org: pravdepodobnost zneuzitia CVE v najblizsich 30 dnoch.
//  NVD      — NIST: popis, CVSS vektor, CWE. Bez API kluca max 5 poziadaviek
//             za 30 s → poziadavky sa radia a cakaju.
//
// Do EPSS a NVD sa posielaju LEN cisla CVE (nie IP adresy, nazvy ani vystup skenu).
// Vysledky sa ukladaju do userData/intel, aby fungovali aj offline.

const fs = require('fs');
const path = require('path');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const DAY = 24 * 60 * 60 * 1000;
const KEV_TTL = DAY;
const NVD_TTL = 7 * DAY;
const NVD_INTERVAL = 6500; // 5 poziadaviek / 30 s bez kluca
const MAX_LOOKUP = 200;
const UA = 'nmap-command-builder-vuln-intel';

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const isCve = (v) => typeof v === 'string' && CVE_RE.test(v);
const str = (v, max = 400) => (typeof v === 'string' ? v.slice(0, max) : '');

/** Z KEV katalogu ponecha len to, co aplikacia pouziva. */
function indexKev(feed) {
  const map = {};
  for (const v of (feed && Array.isArray(feed.vulnerabilities) ? feed.vulnerabilities : [])) {
    if (!isCve(v.cveID)) continue;
    map[v.cveID] = {
      name: str(v.vulnerabilityName, 200),
      vendor: str(v.vendorProject, 80),
      product: str(v.product, 80),
      dateAdded: str(v.dateAdded, 10),
      dueDate: str(v.dueDate, 10),
      ransomware: /^known$/i.test(v.knownRansomwareCampaignUse || ''),
      requiredAction: str(v.requiredAction, 400),
    };
  }
  return { version: str(feed && feed.catalogVersion, 20), released: str(feed && feed.dateReleased, 30), cves: map };
}

/** NVD 2.0 odpoved → kompaktny zaznam (CVSS v3.1 → v4.0 → v3.0 → v2). */
function parseNvd(body) {
  const cve = body && Array.isArray(body.vulnerabilities) && body.vulnerabilities[0] && body.vulnerabilities[0].cve;
  if (!cve || !isCve(cve.id)) return null;
  const m = cve.metrics || {};
  const metric = ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2']
    .map((k) => (Array.isArray(m[k]) ? m[k].find((x) => x.type === 'Primary') || m[k][0] : null))
    .find(Boolean);
  const data = (metric && metric.cvssData) || {};
  const desc = (cve.descriptions || []).find((d) => d.lang === 'en');
  const cwe = [...new Set((cve.weaknesses || []).flatMap((w) => (w.description || []).map((d) => d.value))
    .filter((x) => /^CWE-\d+$/.test(x)))];
  return {
    id: cve.id,
    score: Number.isFinite(data.baseScore) ? data.baseScore : null,
    severity: str(data.baseSeverity || (metric && metric.baseSeverity), 12).toLowerCase(),
    vector: str(data.vectorString, 120),
    cvssVersion: str(data.version, 5),
    cwe: cwe.slice(0, 5),
    published: str(cve.published, 10),
    description: str(desc && desc.value, 700),
  };
}

class VulnIntel {
  /**
   * @param {{ dir: string, fetchFn: Function, now?: () => number, sleep?: (ms) => Promise }} o
   */
  constructor({ dir, fetchFn, now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
    this.dir = dir;
    this.fetchFn = fetchFn;
    this.now = now;
    this.sleep = sleep;
    this.kev = null;
    this.epss = { date: '', data: {} };
    this.nvdQueue = Promise.resolve();
    this.lastNvd = 0;
  }

  file(name) { return path.join(this.dir, name); }

  readJson(name) {
    try { return JSON.parse(fs.readFileSync(this.file(name), 'utf8')); } catch (_) { return null; }
  }

  writeJson(name, data) {
    try {
      fs.mkdirSync(path.dirname(this.file(name)), { recursive: true });
      fs.writeFileSync(this.file(name), JSON.stringify(data));
    } catch (_) { /* cache je nepovinna */ }
  }

  async getJson(url) {
    const res = await this.fetchFn(url, { headers: { Accept: 'application/json', 'User-Agent': UA } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  /** KEV index; obnovi sa raz za den, pri chybe sa pouzije starsia kopia. */
  async loadKev() {
    if (this.kev && this.now() - this.kev.fetchedAt < KEV_TTL) return this.kev;
    const cached = this.kev || this.readJson('kev.json');
    if (cached && cached.cves && this.now() - cached.fetchedAt < KEV_TTL) { this.kev = cached; return cached; }
    try {
      const fresh = { ...indexKev(await this.getJson(KEV_URL)), fetchedAt: this.now() };
      if (Object.keys(fresh.cves).length === 0) throw new Error('empty catalogue');
      this.kev = fresh;
      this.writeJson('kev.json', fresh);
      return fresh;
    } catch (err) {
      if (cached && cached.cves) { this.kev = cached; return { ...cached, stale: true, error: err.message }; }
      throw err;
    }
  }

  /** EPSS pre zoznam CVE (dávky po 100), cache na jeden den. */
  async loadEpss(cves) {
    const today = new Date(this.now()).toISOString().slice(0, 10);
    if (this.epss.date !== today) {
      const disk = this.readJson('epss.json');
      this.epss = disk && disk.date === today && disk.data ? disk : { date: today, data: {} };
    }
    const missing = cves.filter((c) => !(c in this.epss.data));
    for (let i = 0; i < missing.length; i += 100) {
      const chunk = missing.slice(i, i + 100);
      const body = await this.getJson(`${EPSS_URL}?cve=${chunk.join(',')}`);
      chunk.forEach((c) => { this.epss.data[c] = null; }); // CVE bez EPSS skore
      for (const row of (body && Array.isArray(body.data) ? body.data : [])) {
        if (!isCve(row.cve)) continue;
        const epss = parseFloat(row.epss);
        const pct = parseFloat(row.percentile);
        if (Number.isFinite(epss)) this.epss.data[row.cve] = { epss, percentile: Number.isFinite(pct) ? pct : null, date: str(row.date, 10) };
      }
    }
    if (missing.length) this.writeJson('epss.json', this.epss);
    return Object.fromEntries(cves.filter((c) => this.epss.data[c]).map((c) => [c, this.epss.data[c]]));
  }

  nvdCached(cve) {
    const c = this.readJson(path.join('nvd', `${cve}.json`));
    return c && c.data && this.now() - c.fetchedAt < NVD_TTL ? c.data : null;
  }

  /**
   * KEV + EPSS hned, NVD len z cache (detaily sa dotahuju cez nvd()).
   * @returns {{ kev, epss, nvd, meta: { kevVersion, kevStale, errors[] } }}
   */
  async lookup(list) {
    const cves = [...new Set((Array.isArray(list) ? list : []).filter(isCve))].slice(0, MAX_LOOKUP);
    const result = { kev: {}, epss: {}, nvd: {}, meta: { kevVersion: '', kevStale: false, errors: [] } };
    try {
      const kev = await this.loadKev();
      result.meta.kevVersion = kev.version;
      result.meta.kevStale = Boolean(kev.stale);
      cves.forEach((c) => { if (kev.cves[c]) result.kev[c] = kev.cves[c]; });
    } catch (err) {
      result.meta.errors.push(`CISA KEV: ${err.message}`);
    }
    try {
      result.epss = await this.loadEpss(cves);
    } catch (err) {
      result.meta.errors.push(`EPSS: ${err.message}`);
    }
    cves.forEach((c) => { const n = this.nvdCached(c); if (n) result.nvd[c] = n; });
    return result;
  }

  /** Detail jedneho CVE z NVD — v rade, s odstupom podla limitu NVD. */
  nvd(cve) {
    if (!isCve(cve)) return Promise.resolve({ ok: false, error: 'Invalid CVE id' });
    const cached = this.nvdCached(cve);
    if (cached) return Promise.resolve({ ok: true, data: cached, cached: true });
    const run = async () => {
      const again = this.nvdCached(cve);
      if (again) return { ok: true, data: again, cached: true };
      const wait = this.lastNvd + NVD_INTERVAL - this.now();
      if (wait > 0) await this.sleep(wait);
      this.lastNvd = this.now();
      try {
        const data = parseNvd(await this.getJson(`${NVD_URL}?cveId=${cve}`));
        if (!data || data.id !== cve) return { ok: false, error: 'Not found in NVD' };
        this.writeJson(path.join('nvd', `${cve}.json`), { fetchedAt: this.now(), data });
        return { ok: true, data };
      } catch (err) {
        return { ok: false, error: err.message };
      }
    };
    const p = this.nvdQueue.then(run, run);
    this.nvdQueue = p.catch(() => {});
    return p;
  }
}

module.exports = { VulnIntel, indexKev, parseNvd, isCve, KEV_URL, EPSS_URL, NVD_URL, NVD_INTERVAL };
