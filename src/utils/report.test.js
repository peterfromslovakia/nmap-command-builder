import {
  parseHosts, buildReportModel, toMarkdown, toHtml, escapeHtml, overallRisk, normalizeMeta,
} from './report';

const OUT = `Nmap scan report for web.local (192.168.1.10)
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp  open  http    <script>alert(1)</script>
443/tcp closed https
Nmap scan report for 192.168.1.11
PORT   STATE SERVICE
445/tcp open  microsoft-ds
`;

const model = buildReportModel({
  text: OUT, command: 'nmap -sV -sC 192.168.1.0/24', target: '192.168.1.0/24',
  timestamp: '21. 11. 2026 15:00', nmapVersion: 'Nmap version 7.95',
});

test('parseHosts groups open ports per host and skips closed', () => {
  const hosts = parseHosts(OUT);
  expect(hosts.map((h) => h.host)).toEqual(['web.local (192.168.1.10)', '192.168.1.11']);
  expect(hosts[0].ports.map((p) => p.port)).toEqual(['21', '80']);
  expect(hosts[0].ports[0].risk).toBe('high');
});

test('model summarises findings and hardening advice', () => {
  expect(model.openPortCount).toBe(3);
  expect(model.findings.map((f) => f.id)).toEqual(['ftp-anon']);
  expect(model.portAdvice.map((a) => a.port)).toEqual(['21', '445']);
  expect(model.portAdvice[1].hosts).toEqual(['192.168.1.11']);
});

test('markdown contains findings, fixes, ports and raw output', () => {
  const md = toMarkdown(model);
  expect(md).toContain('# Network Security Scan Report');
  expect(md).toContain('[HIGH] Anonymous FTP login allowed');
  expect(md).toContain('**How to fix:**');
  expect(md).toContain('| 21 | tcp | ftp | vsftpd 3.0.3 | HIGH |');
  expect(md).toMatch(/## \d+\. Hardening recommendations/);
  expect(md).toContain('| F-01 | HIGH | Anonymous FTP login allowed | web.local (192.168.1.10) · 21/tcp | — | — | 30 days |');
  expect(md).toContain('**Overall risk: HIGH**');
  expect(md).toContain('- **Performed by:** _not stated_');
  expect(md).toContain('```\nNmap scan report for web.local');
});

test('html escapes untrusted scan data and has a strict CSP', () => {
  const html = toHtml(model);
  expect(html).not.toContain('<script>alert(1)</script>');
  expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  expect(html).toContain("default-src 'none'");
  expect(html).toContain('How to fix');
});

test('escapeHtml', () => {
  expect(escapeHtml(`<a href="x">'&'</a>`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
});

test('empty scan still renders', () => {
  const m = buildReportModel({ text: '', command: 'nmap', target: '', timestamp: '' });
  expect(toMarkdown(m)).toContain('No hosts found');
  expect(toHtml(m)).toContain('No hosts found');
});

describe('comparison with the previous scan', () => {
  // eslint-disable-next-line global-require
  const { makeSnapshot, diffScans } = require('./scanDiff');
  const before = makeSnapshot({ id: 1, time: 't1', target: 'x', command: 'nmap -sV x', text: OUT });
  const after = makeSnapshot({
    id: 2, time: 't2', target: 'x', command: 'nmap -sV x',
    text: OUT.replace('| ftp-anon: Anonymous FTP login allowed (FTP code 230)\n', '')
      .replace('445/tcp open  microsoft-ds', '445/tcp open  microsoft-ds\n3389/tcp open  ms-wbt-server <b>RDP</b>'),
  });
  const withCmp = (diff) => buildReportModel({
    text: OUT, command: 'c', target: 'x', timestamp: 'now',
    comparison: { baselineTime: '20. 11. 10:00', baselineCommand: 'nmap -sV x', diff },
  });

  test('model has no comparison unless one is passed', () => {
    expect(model.comparison).toBeNull();
    expect(toMarkdown(model)).not.toContain('Changes since previous scan');
  });

  test('changes appear in markdown and escaped in html', () => {
    const m = withCmp(diffScans(before, after));
    expect(m.comparison.sections.map((s) => s.title)).toEqual(['New open ports', 'Fixed vulnerabilities']);
    const md = toMarkdown(m);
    expect(md).toMatch(/## \d+\. Changes since previous scan/);
    expect(md).toContain('3389/tcp ms-wbt-server');
    expect(md.search(/## \d+\. Changes since/)).toBeGreaterThan(md.search(/## \d+\. Vulnerabilities & fixes/));
    const html = toHtml(m);
    expect(html).toContain('&lt;b&gt;RDP&lt;/b&gt;');
    expect(html).not.toContain('<b>RDP</b>');
  });

  test('identical scans report "No changes"', () => {
    expect(toMarkdown(withCmp(diffScans(before, before)))).toContain('_No changes._');
  });
});

describe('report details, overall risk and language', () => {
  const META = {
    lang: 'sk', tester: 'Ján Tester', organization: 'ACME s.r.o.', client: 'Obec X', authorization: 'ZML-2026/14',
  };
  const sk = buildReportModel({ text: OUT, command: 'nmap -sV x', target: 'x', timestamp: '21. 11. 2026', meta: META });

  test('meta is trimmed, single-line and limited; unknown language falls back to English', () => {
    expect(normalizeMeta({ lang: 'de', tester: ' A\nB ', client: 'x'.repeat(300) })).toEqual({
      lang: 'en', tester: 'A B', organization: '', client: 'x'.repeat(120), authorization: '',
    });
  });

  test('overall risk follows the worst finding, then risky ports', () => {
    const cmd = 'nmap -sV 192.168.1.1';
    expect(overallRisk([{ severity: 'low' }, { severity: 'critical' }], [], cmd)).toBe('critical');
    expect(overallRisk([], [{ ports: [{ risk: 'high' }] }], cmd)).toBe('medium');
    expect(overallRisk([], [{ ports: [{ risk: 'medium' }] }], cmd)).toBe('low');
    expect(overallRisk([], [{ ports: [{ risk: 'safe' }] }], cmd)).toBe('none');
    expect(model.risk).toBe('high');
  });

  test('overall risk is not_assessed for discovery scans', () => {
    expect(overallRisk([{ severity: 'low' }], [{ ports: [{ risk: 'high' }] }], 'nmap -sn 192.168.1.0/24')).toBe('not_assessed');
    expect(overallRisk([], [], 'nmap -sn 192.168.1.0/24')).toBe('not_assessed');
  });

  test('overall risk is port_only for basic port scan (no -sV, no --script)', () => {
    expect(overallRisk([], [{ ports: [{ risk: 'safe' }] }], 'nmap 192.168.50.0/24')).toBe('port_only');
    expect(overallRisk([], [], 'nmap -p 1-1000 10.0.0.1')).toBe('port_only');
    // -sV alone is 'none' (service detection ran, no vuln scripts but more info than bare scan)
    expect(overallRisk([], [{ ports: [{ risk: 'safe' }] }], 'nmap -sV 192.168.1.1')).toBe('none');
  });

  test('Slovak markdown: labels, translated findings and fixes, tester details', () => {
    const md = toMarkdown(sk);
    expect(md).toContain('# Správa o bezpečnostnom skene siete');
    expect(md).toContain('- **Test vykonal:** Ján Tester');
    expect(md).toContain('- **Organizácia:** ACME s.r.o.');
    expect(md).toContain('- **Klient / vlastník systému:** Obec X');
    expect(md).toContain('- **Číslo poverenia:** ZML-2026/14');
    expect(md).toContain('[VYSOKÉ] Povolené anonymné prihlásenie na FTP');
    expect(md).toContain('**Ako opraviť:**');
    expect(md).toContain('Vypnite anonymné prihlásenie');
    expect(md).toMatch(/## \d+\. Rozsah a metodika/);
    expect(md).not.toContain('How to fix');
  });

  test('Slovak html escapes tester details too', () => {
    const html = toHtml({ ...sk, tester: '<img src=x>' });
    expect(html).toContain('<html lang="sk">');
    expect(html).toContain('Test vykonal');
    expect(html).toContain('&lt;img src=x&gt;');
    expect(html).not.toContain('<img src=x>');
  });
});

describe('pentest-grade report', () => {
  const VULN = `Nmap scan report for fileserver.lan (192.168.1.20)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1
| vulners:
|   cpe:/a:openbsd:openssh:8.2p1:
|     	CVE-2023-38408	9.8	https://vulners.com/cve/CVE-2023-38408
|_    	CVE-2021-41617	7.0	https://vulners.com/cve/CVE-2021-41617
445/tcp open  microsoft-ds
Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
`;
  const { parseFindings } = jest.requireActual('./findings');
  const { applyIntel } = jest.requireActual('./intel');
  const intel = {
    kev: { 'CVE-2017-0143': { dueDate: '2022-05-03', ransomware: true } },
    epss: { 'CVE-2017-0143': { epss: 0.933, percentile: 0.99 }, 'CVE-2023-38408': { epss: 0.8, percentile: 0.98 } },
    nvd: { 'CVE-2023-38408': { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: ['CWE-428'], description: 'ssh-agent <PKCS#11> RCE' } },
  };
  const make = (lang, extra = {}) => buildReportModel({
    text: VULN, command: 'nmap -sV --script vuln,vulners -T4 192.168.1.20', target: '192.168.1.20', timestamp: 't',
    findings: applyIntel(parseFindings(VULN), intel), intelMeta: { kevVersion: '2026.11.20' }, meta: { lang, tester: 'Ján' }, ...extra,
  });

  test('findings get IDs, KEV flag, NVD CVSS/CWE and remediation timeframe', () => {
    const m = make('en');
    expect(m.findings.map((f) => [f.ref, f.exploited, f.timeframe])).toEqual([
      ['F-01', true, 'exploited'], ['F-02', false, 'critical'],
    ]);
    expect(m.findings[1]).toMatchObject({ cvss: 9.8, cwe: ['CWE-428'], nvdDescriptionCve: 'CVE-2023-38408' });
    expect(m.exploitedCount).toBe(1);
    expect(m.actions[0]).toMatchObject({ ref: 'F-01', exploited: true });
  });

  test('methodology describes the techniques actually used', () => {
    const m = make('en');
    expect(m.techniques).toEqual(expect.arrayContaining([
      'TCP connect port scan', 'Service and version detection', 'Nmap Scripting Engine (NSE): vuln,vulners', 'Timing template T4',
    ]));
    expect(m.techniques.join()).toMatch(/CISA KEV/);
  });

  test('HTML has cover, contents, rating table, sign-off; untrusted text escaped', () => {
    const html = toHtml(make('sk'));
    ['class="cover"', 'Obsah', 'Hodnotenie rizika a termíny opráv', 'Okamžite', 'Schválenie', 'F-01', 'CWE-428', 'CISA KEV 2026.11.20'].forEach((s) => expect(html).toContain(s));
    expect(html).toContain('&lt;PKCS#11&gt;');
    expect(html).not.toContain('<PKCS#11>');
  });

  test('markdown: numbered chapters and asset inventory when provided', () => {
    const inventory = [{ ip: '192.168.1.1', type: 'router', hostname: 'gw', mac: 'AA:BB:CC:00:11:22', vendor: 'Ubiquiti', randomizedMac: false, ports: [{ port: 53 }, { port: 443 }] }];
    const md = toMarkdown(make('en', { inventory }));
    expect(md).toMatch(/## \d+\. Asset inventory/);
    expect(md).toContain('| 192.168.1.1 | Router / gateway | gw | AA:BB:CC:00:11:22 · Ubiquiti | 53, 443 |');
    expect(md).toMatch(/### F-01 — \[HIGH|CRITICAL\]/);
    expect(md).toContain('Actively exploited (CISA KEV) — used in ransomware campaigns');
  });
});

test('table of contents numbers every section explicitly (10+ must not be clipped)', () => {
  const { buildReportModel: b, toHtml: h } = require('./report');
  const html = h(b({ text: '', command: 'nmap x', target: 'x', timestamp: 't' }));
  const toc = html.slice(html.indexOf('class="toc"'), html.indexOf('</ol>', html.indexOf('class="toc"')));
  const nums = [...toc.matchAll(/class="toc__n">(\d+)\./g)].map((x) => Number(x[1]));
  expect(nums.length).toBeGreaterThan(3);
  expect(nums).toEqual(nums.map((_, i) => i + 1));
});

describe('network map appendix', () => {
  const { buildReportModel: b, toHtml: h, toMarkdown: md, reportSections: rs } = require('./report');
  const dev = (ip, type, ports = [], extra = {}) => ({ ip, type, hostname: '', mac: '', vendor: '', os: '', ports: ports.map((port) => ({ port, proto: 'tcp', service: 's', version: '' })), ...extra });
  const inventory = [dev('10.0.0.1', 'router', [53, 80], { hostname: 'gw.lan' }), dev('10.0.0.5', 'windows', [445]), dev('10.0.0.9', 'linux', [22])];
  const findings = [{ id: 'x', title: 'EternalBlue', host: 'pc (10.0.0.5)', severity: 'critical', exploited: true, fix: [], refs: [] }];

  test('appendix A before raw output, refs and KEV on the device, own computer marked', () => {
    const m = b({ text: '', command: 'nmap -sn 10.0.0.0/24', target: '10.0.0.0/24', timestamp: 't', inventory, findings, gatewayIp: '10.0.0.1', localIps: ['10.0.0.9'], meta: { lang: 'en' } });
    const ids = rs(m).map((x) => x.id);
    expect(ids.slice(-2)).toEqual(['map', 'raw']);
    expect(m.map.gateway.ip).toBe('10.0.0.1');
    const win = m.map.groups.find((g) => g.type === 'windows').devices[0];
    expect(win).toMatchObject({ refs: ['F-01'], risk: { level: 'critical', exploited: true } });
    const html = h(m);
    expect(html).toContain('Appendix A — network map');
    expect(html).toMatch(/nm-node nm-critical[\s\S]*10\.0\.0\.5[\s\S]*F-01[\s\S]*CISA KEV/);
    expect(html).toContain('scanning computer');
    const text = md(m);
    expect(text).toMatch(/└─ Router \/ gateway: 10\.0\.0\.1 gw\.lan/);
    expect(text).toMatch(/10\.0\.0\.5 — Critical vulnerability F-01 CISA KEV/);
    expect(text).toMatch(/```\n\n## \d+\. Appendix B/);
  });

  test('Slovak labels and no map for single host scans', () => {
    const m = b({ text: '', command: 'nmap x', target: 'x', timestamp: 't', inventory, findings, meta: { lang: 'sk' } });
    expect(h(m)).toContain('Príloha A — mapa siete');
    expect(h(m)).toContain('Lokálna sieť x · 2 zariadenia');
    expect(b({ text: '', command: 'nmap x', target: 'x', timestamp: 't', inventory: [inventory[0]] }).map).toBeNull();
  });
});

describe('NSE errors in report output (F-004 export)', () => {
  const NSE_TEXT = `Nmap scan report for 192.168.1.5
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_ERROR: Script execution failed (use -d to debug)
Nmap done.
`;

  const NSE_XSS_TEXT = `Nmap scan report for 192.168.1.5
PORT   STATE SERVICE
80/tcp open  http
| http-scripts:
|_ERROR: <script>alert(1)</script>
Nmap done.
`;

  const makeModel = (text, lang = 'en') =>
    buildReportModel({ text, command: 'nmap -sC 192.168.1.5', target: '192.168.1.5', timestamp: 't', meta: { lang } });

  test('toMarkdown: NSE errors table rendered when nseErrors present', () => {
    const md = toMarkdown(makeModel(NSE_TEXT));
    expect(md).toContain('NSE script errors');
    expect(md).toContain('http-enum');
    expect(md).toContain('Script execution failed');
  });

  test('toMarkdown: NSE section absent when no errors', () => {
    const md = toMarkdown(makeModel('Nmap scan report for 192.168.1.5\nNmap done.\n'));
    expect(md).not.toContain('NSE script errors');
  });

  test('toHtml: NSE errors table rendered with escaping', () => {
    const html = toHtml(makeModel(NSE_XSS_TEXT));
    expect(html).toContain('nse-err-section');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
  });

  test('toHtml: NSE section absent when no errors', () => {
    const html = toHtml(makeModel('Nmap scan report for 192.168.1.5\nNmap done.\n'));
    expect(html).not.toContain('nse-err-section');
  });

  test('toMarkdown SK: NSE errors section uses Slovak label', () => {
    const md = toMarkdown(makeModel(NSE_TEXT, 'sk'));
    expect(md).toContain('Chyby NSE skriptov');
  });
});

describe('report accuracy fixes (phase-4b)', () => {
  const mk = (command, text = '', extra = {}) =>
    buildReportModel({ text, command, target: '192.168.50.0/24', timestamp: 't', ...extra });

  // Fix 1 & 2: port_only risk + noFindingsNotTested text
  test('basic port scan: risk=port_only, findings section uses noFindingsNotTested', () => {
    const m = mk('nmap 192.168.50.0/24');
    expect(m.risk).toBe('port_only');
    const md = toMarkdown(m);
    expect(md).toContain('port_only' in m ? '' : ''); // model has risk
    expect(md).not.toContain('Spustené NSE skripty nenašli');
    expect(md).not.toContain('No known vulnerabilities were detected by the NSE scripts');
    expect(md).toContain('Vulnerability testing was not performed');
  });

  test('basic port scan SK: noFindingsNotTested in Slovak', () => {
    const m = mk('nmap 192.168.50.0/24', '', { meta: { lang: 'sk' } });
    expect(toMarkdown(m)).toContain('nebolo vykonané testovanie zraniteľností');
  });

  test('-sV scan: risk=none (service detection ran, no vuln scripts is acceptable)', () => {
    const m = mk('nmap -sV 192.168.50.0/24');
    expect(m.risk).toBe('none');
  });

  test('-sC scan: risk=none (default scripts = vuln category)', () => {
    const m = mk('nmap -sC 192.168.50.0/24');
    expect(m.risk).toBe('none');
  });

  // Fix 3: scan time from nmap output
  test('parseScanTimes extracts start time and elapsed from nmap output', () => {
    const { parseScanTimes } = require('./report');
    const text = `Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-22 09:14 CET
Nmap scan report for 192.168.50.1
PORT   STATE SERVICE
80/tcp open  http
Nmap done: 1 IP address (1 host up) scanned in 50.42 seconds`;
    const { startLine, elapsedSeconds } = parseScanTimes(text);
    expect(startLine).toMatch(/2026-11-22 09:14/);
    expect(elapsedSeconds).toBe(50.42);
  });

  test('report uses nmap start time (not JS Date) when available', () => {
    const text = `Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-22 09:14 CET
Nmap done: 1 IP address (1 host up) scanned in 10.00 seconds`;
    const m = mk('nmap 192.168.50.0/24', text);
    expect(m.nmapStartLine).toMatch(/2026-11-22 09:14/);
    expect(m.nmapElapsed).toBe(10.0);
    const md = toMarkdown(m);
    expect(md).toContain('2026-11-22 09:14');
    expect(md).toContain('10 s');
  });

  // Fix 4: two localIps → secondary interface label
  test('second localIp gets secondary interface label in report', () => {
    const devs = [
      { ip: '192.168.50.100', type: 'unknown', hostname: '', mac: '', vendor: '', os: '', ports: [] },
      { ip: '192.168.1.5', type: 'unknown', hostname: '', mac: '', vendor: '', os: '', ports: [] },
      { ip: '192.168.50.1', type: 'router', hostname: '', mac: '', vendor: '', os: '', ports: [] },
    ];
    const m = buildReportModel({ text: '', command: 'nmap 192.168.50.0/24', target: '192.168.50.0/24',
      timestamp: 't', inventory: devs, localIps: ['192.168.50.100', '192.168.1.5'] });
    const html = toHtml(m);
    expect(html).toContain('scanning computer');
    expect(html).toContain('secondary interface');
    // must not say "scanning computer" twice as primary
    const primaryCount = (html.match(/scanning computer(?! — secondary)/g) || []).length;
    expect(primaryCount).toBe(1);
  });

  // Fix 5: service guess note without -sV
  test('without -sV: service-guess note in markdown', () => {
    const m = mk('nmap 192.168.50.0/24', 'Nmap scan report for 192.168.50.1\nPORT   STATE SERVICE\n80/tcp open  http\n');
    expect(m.serviceDetection).toBe(false);
    expect(toMarkdown(m)).toContain('estimates based on port numbers');
  });

  test('with -sV: no service-guess note', () => {
    const m = mk('nmap -sV 192.168.50.0/24', 'Nmap scan report for 192.168.50.1\nPORT   STATE SERVICE\n80/tcp open  http\n');
    expect(m.serviceDetection).toBe(true);
    expect(toMarkdown(m)).not.toContain('estimates based on port numbers');
  });
});

test('map appendix: firewall gateway label and one frame per scanned range', () => {
  const { buildReportModel: b, toHtml: h, toMarkdown: md } = require('./report');
  const dev = (ip, type) => ({ ip, type, hostname: '', mac: '', vendor: '', os: '', ports: [] });
  const m = b({ text: '', command: 'nmap -sn 10.0.0.0/22 192.168.5.0/24', target: '10.0.0.0/22 192.168.5.0/24', timestamp: 't', meta: { lang: 'sk' },
    inventory: [dev('10.0.0.1', 'firewall'), dev('10.0.3.7', 'windows'), dev('192.168.5.9', 'printer')], gatewayIp: '10.0.0.1' });
  const html = h(m);
  expect(html).toContain('Lokálna sieť 10.0.0.0/22 · 1 zariadenie');
  expect(html).toContain('Lokálna sieť 192.168.5.0/24 · 1 zariadenie');
  expect(html).toMatch(/nm-gw__type">Firewall</);
  expect(md(m)).toMatch(/└─ Firewall: 10\.0\.0\.1[\s\S]*├─ Lokálna sieť 10\.0\.0\.0\/22[\s\S]*└─ Lokálna sieť 192\.168\.5\.0\/24/);
});
