const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { VulnIntel, indexKev, parseNvd, KEV_URL, NVD_INTERVAL } = require('./vulnIntel');

const KEV = {
  catalogVersion: '2026.11.20',
  dateReleased: '2026-11-20T17:48:39Z',
  vulnerabilities: [
    { cveID: 'CVE-2017-0143', vendorProject: 'Microsoft', product: 'SMBv1', vulnerabilityName: 'Microsoft Windows SMB RCE', dateAdded: '2022-02-10', dueDate: '2022-08-10', knownRansomwareCampaignUse: 'Known', requiredAction: 'Apply updates per vendor instructions.' },
    { cveID: 'not-a-cve', vulnerabilityName: 'x' },
  ],
};
const NVD = {
  vulnerabilities: [{ cve: {
    id: 'CVE-2023-38408', published: '2023-07-20T03:15:10.170',
    descriptions: [{ lang: 'es', value: 'x' }, { lang: 'en', value: 'The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 …' }],
    metrics: {
      cvssMetricV2: [{ cvssData: { baseScore: 5, vectorString: 'AV:N', version: '2.0' } }],
      cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', version: '3.1' } }],
    },
    weaknesses: [{ description: [{ value: 'CWE-428' }] }, { description: [{ value: 'CWE-428' }, { value: 'NVD-CWE-noinfo' }] }],
  } }],
};

function setup(routes, opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncb-intel-'));
  const calls = [];
  let t = opts.start || Date.UTC(2026, 10, 21, 12);
  const sleeps = [];
  const intel = new VulnIntel({
    dir,
    now: () => t,
    sleep: async (ms) => { sleeps.push(ms); t += ms; },
    fetchFn: async (url) => {
      calls.push(url);
      const r = routes(url);
      if (r instanceof Error) throw r;
      return { ok: r.status ? r.status === 200 : true, status: r.status || 200, json: async () => r.body ?? r };
    },
  });
  return { intel, calls, sleeps, dir, advance: (ms) => { t += ms; } };
}

const routes = (url) => {
  if (url === KEV_URL) return KEV;
  if (url.includes('api.first.org')) return { data: [{ cve: 'CVE-2017-0143', epss: '0.93307', percentile: '0.99841', date: '2026-11-21' }] };
  if (url.includes('nvd.nist.gov')) return NVD;
  return { status: 404, body: {} };
};

test('indexKev keeps only valid CVEs and the fields the app uses', () => {
  const k = indexKev(KEV);
  assert.deepStrictEqual(Object.keys(k.cves), ['CVE-2017-0143']);
  assert.strictEqual(k.cves['CVE-2017-0143'].ransomware, true);
  assert.strictEqual(k.version, '2026.11.20');
  assert.deepStrictEqual(indexKev(null).cves, {});
});

test('parseNvd prefers CVSS 3.1 primary metric, dedupes CWE, English description', () => {
  assert.deepStrictEqual(parseNvd(NVD), {
    id: 'CVE-2023-38408', score: 9.8, severity: 'critical', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssVersion: '3.1', cwe: ['CWE-428'], published: '2023-07-20',
    description: 'The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 …',
  });
  assert.strictEqual(parseNvd({ vulnerabilities: [] }), null);
});

test('lookup: KEV + EPSS, only CVE ids are sent, invalid ids dropped', async () => {
  const { intel, calls } = setup(routes);
  const r = await intel.lookup(['CVE-2017-0143', 'CVE-2023-38408', '192.168.1.1', 'CVE-2017-0143', '../etc']);
  assert.deepStrictEqual(Object.keys(r.kev), ['CVE-2017-0143']);
  assert.strictEqual(r.epss['CVE-2017-0143'].epss, 0.93307);
  assert.strictEqual(r.epss['CVE-2023-38408'], undefined);
  assert.strictEqual(r.meta.kevVersion, '2026.11.20');
  assert.deepStrictEqual(r.meta.errors, []);
  const epssCall = calls.find((u) => u.includes('first.org'));
  assert.strictEqual(epssCall, 'https://api.first.org/data/v1/epss?cve=CVE-2017-0143,CVE-2023-38408');
  assert.ok(!calls.some((u) => u.includes('192.168')));
});

test('caching: KEV once a day, EPSS once a day per CVE, survives restart (disk)', async () => {
  const s = setup(routes);
  await s.intel.lookup(['CVE-2017-0143']);
  await s.intel.lookup(['CVE-2017-0143']);
  assert.strictEqual(s.calls.filter((u) => u === KEV_URL).length, 1);
  assert.strictEqual(s.calls.filter((u) => u.includes('first.org')).length, 1);

  const again = new VulnIntel({ dir: s.dir, now: () => Date.UTC(2026, 10, 21, 18), fetchFn: async () => { throw new Error('offline'); } });
  const r = await again.lookup(['CVE-2017-0143']);
  assert.ok(r.kev['CVE-2017-0143']);
  assert.ok(r.epss['CVE-2017-0143']);
  assert.deepStrictEqual(r.meta.errors, []);
});

test('offline after expiry: stale KEV is used and reported, EPSS error is reported', async () => {
  const s = setup(routes);
  await s.intel.lookup(['CVE-2017-0143']);
  const later = new VulnIntel({ dir: s.dir, now: () => Date.UTC(2026, 10, 25), fetchFn: async () => { throw new Error('offline'); } });
  const r = await later.lookup(['CVE-2017-0143']);
  assert.ok(r.kev['CVE-2017-0143']);
  assert.strictEqual(r.meta.kevStale, true);
  assert.match(r.meta.errors.join(), /EPSS: offline/);

  const empty = setup(() => new Error('offline'));
  const r2 = await empty.intel.lookup(['CVE-2017-0143']);
  assert.deepStrictEqual(r2.kev, {});
  assert.strictEqual(r2.meta.errors.length, 2);
});

test('NVD: rate limited queue, cached for later lookups', async () => {
  const s = setup(routes);
  const [a, b] = await Promise.all([s.intel.nvd('CVE-2023-38408'), s.intel.nvd('CVE-2023-38409')]);
  assert.strictEqual(a.ok, true);
  assert.strictEqual(a.data.score, 9.8);
  assert.deepStrictEqual(b, { ok: false, error: 'Not found in NVD' }); // odpoved pre iny CVE sa neulozi
  assert.ok(s.sleeps.some((ms) => ms === NVD_INTERVAL), `waited ${s.sleeps}`);
  const before = s.calls.length;
  assert.strictEqual((await s.intel.nvd('CVE-2023-38408')).cached, true);
  assert.strictEqual(s.calls.length, before);
  const r = await s.intel.lookup(['CVE-2023-38408']);
  assert.strictEqual(r.nvd['CVE-2023-38408'].score, 9.8);
  assert.deepStrictEqual(await s.intel.nvd('CVE-1;rm'), { ok: false, error: 'Invalid CVE id' });
});
