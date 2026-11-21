import { parseHosts, buildReportModel, toMarkdown, toHtml, escapeHtml } from './report';

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
  expect(md).toContain('# Nmap Scan Report');
  expect(md).toContain('[HIGH] Anonymous FTP login allowed');
  expect(md).toContain('**How to fix:**');
  expect(md).toContain('| 21 | tcp | ftp | vsftpd 3.0.3 | HIGH |');
  expect(md).toContain('## Hardening Recommendations');
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
    expect(toMarkdown(model)).not.toContain('Changes Since Previous Scan');
  });

  test('changes appear in markdown and escaped in html', () => {
    const m = withCmp(diffScans(before, after));
    expect(m.comparison.sections.map((s) => s.title)).toEqual(['New open ports', 'Fixed vulnerabilities']);
    const md = toMarkdown(m);
    expect(md).toContain('## Changes Since Previous Scan');
    expect(md).toContain('3389/tcp ms-wbt-server');
    expect(md.indexOf('Changes Since')).toBeLessThan(md.indexOf('Vulnerabilities & Fixes'));
    const html = toHtml(m);
    expect(html).toContain('&lt;b&gt;RDP&lt;/b&gt;');
    expect(html).not.toContain('<b>RDP</b>');
  });

  test('identical scans report "No changes"', () => {
    expect(toMarkdown(withCmp(diffScans(before, before)))).toContain('_No changes._');
  });
});
