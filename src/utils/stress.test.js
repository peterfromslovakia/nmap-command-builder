// Zatazove a okrajove pripady — rozne siete u roznych pouzivatelov.
import { buildInventory } from './inventory';
import { parseFindings } from './findings';
import { buildTopology } from './topology';
import { buildReportModel, toHtml, toMarkdown } from './report';
import { makeSnapshot, diffScans } from './scanDiff';

const host = (ip, name, ports = [], extra = '') => [
  `Nmap scan report for ${name ? `${name} (${ip})` : ip}`,
  'Host is up (0.0031s latency).',
  ...(ports.length ? ['PORT     STATE SERVICE VERSION', ...ports.map(([p, svc, ver]) => `${p}/tcp open  ${svc} ${ver || ''}`)] : []),
  ...(extra ? [extra] : []),
].join('\n');

/** n zariadeni v sieti 10.0.0.0/20 (az 4094 adries). */
function bigNetwork(n) {
  const out = ['Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-21 20:00 CET'];
  for (let i = 0; i < n; i++) {
    const ip = `10.0.${Math.floor((i + 1) / 254)}.${((i + 1) % 254) + 1}`;
    const kind = i % 5;
    const ports = kind === 0 ? [[445, 'microsoft-ds'], [3389, 'ms-wbt-server']] : kind === 1 ? [[22, 'ssh', 'OpenSSH 9.2']] : kind === 2 ? [[9100, 'jetdirect']] : [];
    out.push(host(ip, i % 3 ? `pc-${i}.firma.local` : '', ports, ports.length ? '' : `MAC Address: 00:11:22:${String(i % 100).padStart(2, '0')}:AA:BB (Dell)`));
  }
  out.push(`Nmap done: 4096 IP addresses (${n} hosts up) scanned in 300.00 seconds`);
  return out.join('\n');
}

describe('large networks', () => {
  const text = bigNetwork(3000);

  test('3 000 devices: inventory, map and report stay complete and fast', () => {
    const t0 = Date.now();
    const inv = buildInventory(text);
    expect(inv).toHaveLength(3000);
    const topo = buildTopology({ devices: inv, target: '10.0.0.0/20' });
    expect(topo.total).toBe(3000);
    expect(topo.segments).toHaveLength(1);
    const m = buildReportModel({ text, command: 'nmap -sV 10.0.0.0/20', target: '10.0.0.0/20', timestamp: 't', inventory: inv });
    const html = toHtml(m);
    const md = toMarkdown(m);
    expect(Date.now() - t0).toBeLessThan(8000);
    const last = inv[inv.length - 1].ip; // posledne zariadenie je v reporte
    expect(last).toBe('10.0.11.207');
    expect(html).toContain(`<b>${last}</b>`);
    expect(md).toContain(last);
    // PDF sa posiela do main procesu s limitom 20 MB
    expect(html.length).toBeLessThan(20 * 1024 * 1024);
  });

  test('very long raw output is shortened in the report appendix, not dropped silently', () => {
    const huge = `${text}\n${'x'.repeat(100)}\n`.repeat(20); // ~ niekolko MB
    const m = buildReportModel({ text: huge, command: 'nmap', target: '10.0.0.0/20', timestamp: 't', meta: { lang: 'sk' } });
    expect(m.raw.length).toBeLessThan(2.2 * 1024 * 1024);
    expect(m.rawTruncated).toBe(true);
    expect(toHtml(m)).toContain('skrátený');
    expect(toMarkdown(m)).toContain('skrátený');
  });

  test('scan comparison of two large networks', () => {
    const a = makeSnapshot({ id: 1, time: 't', target: 'x', command: 'c', text });
    const b = makeSnapshot({ id: 2, time: 't', target: 'x', command: 'c', text: bigNetwork(2990) });
    const d = diffScans(a, b);
    expect(d.goneHosts.length).toBe(10);
  });
});

describe('unusual output', () => {
  test('IPv6 hosts do not break inventory, map or report', () => {
    const text = [host('fe80::1c2b:3aff:fe4d:5e6f', 'router.lan', [[53, 'domain'], [80, 'http']]),
      host('2001:db8::25', '', [[22, 'ssh']])].join('\n');
    const inv = buildInventory(text);
    expect(inv.map((d) => d.ip)).toEqual(['fe80::1c2b:3aff:fe4d:5e6f', '2001:db8::25']);
    const topo = buildTopology({ devices: inv, target: 'fe80::/64', gatewayIp: '192.168.1.1' });
    expect(topo.total).toBe(2);
    expect(() => toHtml(buildReportModel({ text, command: 'nmap -6 x', target: 'fe80::/64', timestamp: 't', inventory: inv }))).not.toThrow();
  });

  test('empty, "0 hosts up" and interrupted scans', () => {
    ['', 'Nmap done: 256 IP addresses (0 hosts up) scanned in 2.10 seconds',
      'Nmap scan report for 10.0.0.5\nHost is up.\nPORT   STATE SERVICE\n22/tcp open  s', // prerusene uprostred
    ].forEach((text) => {
      expect(() => buildInventory(text)).not.toThrow();
      expect(() => parseFindings(text)).not.toThrow();
      const m = buildReportModel({ text, command: 'nmap x', target: 'x', timestamp: 't' });
      expect(() => toHtml(m)).not.toThrow();
      expect(() => toMarkdown(m)).not.toThrow();
    });
  });

  test('Windows line endings (CRLF)', () => {
    const text = host('192.168.1.20', 'nas.lan', [[445, 'microsoft-ds'], [5000, 'http', 'nginx']]).replace(/\n/g, '\r\n');
    const inv = buildInventory(text);
    expect(inv[0]).toMatchObject({ ip: '192.168.1.20', hostname: 'nas.lan' });
    expect(inv[0].ports.map((p) => p.port)).toEqual([445, 5000]);
  });

  test('hostile banners and names are escaped in the report (no HTML/script injection)', () => {
    const evil = '<img src=x onerror=alert(1)><script>alert(2)</script>';
    const text = host('10.0.0.9', 'evil.lan', [[80, 'http', evil]], `Service Info: Device: ${evil}`)
      + '\n' + host('10.0.0.10', 'b.lan', [[22, 'ssh']]);
    const inv = buildInventory(text);
    const html = toHtml(buildReportModel({ text, command: 'nmap -sV 10.0.0.0/24', target: '10.0.0.0/24', timestamp: 't', inventory: inv }));
    expect(html).not.toContain('<script>alert');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;script&gt;');
  });
});
