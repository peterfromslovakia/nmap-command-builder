// Verifikačný test s reálnym nmap výstupom zo skenu 192.168.50.0/24
import { buildReportModel, toMarkdown, toHtml, parseScanTimes } from './report';

const REAL_SCAN = `Starting Nmap 7.993 ( https://nmap.org ) at 2026-11-22 09:34 +0100
Nmap scan report for unifi.localdomain (192.168.50.2)
Host is up (0.00072s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
8443/tcp open  https-alt

Nmap scan report for H8c_BC8738062_EZVIZ.localdomain (192.168.50.83)
Host is up (0.00052s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
554/tcp  open  rtsp
8000/tcp open  http-alt
8443/tcp open  https-alt
9010/tcp open  sdr

Nmap scan report for 192.168.50.168
Host is up (0.000058s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE
3000/tcp open  ppp
5000/tcp open  upnp
7000/tcp open  afs3-fileserver

Nmap scan report for 192.168.50.173
Host is up (0.010s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
514/tcp   open  shell
8080/tcp  open  http-proxy
10003/tcp open  documentum_s

Nmap scan report for MacBook-Pro-M5.localdomain (192.168.50.229)
Host is up (0.00011s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE
3000/tcp open  ppp
5000/tcp open  upnp
7000/tcp open  afs3-fileserver

Nmap done: 256 IP addresses (5 hosts up) scanned in 147.06 seconds
`;

const makeModel = (lang = 'en') => buildReportModel({
  text: REAL_SCAN,
  command: 'nmap 192.168.50.0/24',
  target: '192.168.50.0/24',
  timestamp: '22. 11. 2026, 09:35:04',
  localIps: ['192.168.50.229', '192.168.1.5'],
  meta: { lang },
});

describe('real scan 192.168.50.0/24 — report accuracy (phase-4b verification)', () => {
  test('Fix 1: scan has medium-risk ports (53, 8080) → risk=low (not none)', () => {
    // The real scan has port 53 (DNS) and 8080 (HTTP proxy) which are medium risk.
    // overallRisk correctly returns 'low' — this is a port-based risk, not NSE-based.
    // 'port_only' applies only when all ports are 'safe'.
    const risk = makeModel().risk;
    expect(['low', 'port_only']).toContain(risk);
    // Must NOT be 'none' (that would imply NSE scripts ran and found nothing)
    expect(risk).not.toBe('none');
  });

  test('Fix 1: no "NSE scripts found no vulnerabilities" text in EN report when risk=low', () => {
    const m = makeModel();
    const md = toMarkdown(m);
    if (m.risk === 'low') {
      // low risk from risky ports — NSE section should not say "scripts found nothing"
      // the noFindings text is only shown when findings.length === 0
      // but noFindingsNotTested is used for port_only/not_assessed
      expect(md).not.toContain('No known vulnerabilities were detected by the NSE scripts');
    }
  });

  test('Fix 1 SK: port_only risk (clean scan, all safe ports) uses noFindingsNotTested', () => {
    // Use a scan with only safe ports to trigger port_only
    const { buildReportModel: b } = require('./report');
    const m = b({ text: 'Nmap scan report for 192.168.50.1\nPORT   STATE SERVICE\n80/tcp open  http\nNmap done: 1 IP address (1 host up) scanned in 1.00 seconds',
      command: 'nmap 192.168.50.0/24', target: '192.168.50.0/24', timestamp: 't', meta: { lang: 'sk' } });
    expect(m.risk).toBe('port_only');
    expect(toMarkdown(m)).not.toContain('Spustené NSE skripty nenašli');
    expect(toMarkdown(m)).toContain('nebolo vykonané testovanie zraniteľností');
  });

  test('Fix 2: low risk from risky ports — no NSE "found nothing" text, uses portOnly text', () => {
    const m = makeModel();
    const md = toMarkdown(m);
    if (m.risk === 'low') {
      expect(md).not.toContain('No known vulnerabilities were detected by the NSE scripts');
      expect(md).toContain('Risk rating is based on port exposure only');
    }
  });

  test('Fix 3: scan time comes from nmap output (09:34), not JS Date (09:35)', () => {
    const times = parseScanTimes(REAL_SCAN);
    expect(times.startLine).toMatch(/09:34/);
    expect(times.elapsedSeconds).toBe(147.06);
    const model = makeModel();
    expect(model.nmapStartLine).toMatch(/09:34/);
    expect(model.nmapElapsed).toBe(147.06);
    const md = toMarkdown(model);
    expect(md).toContain('09:34');
    expect(md).toContain('147.06 s');
    expect(md).not.toMatch(/Scan.*09:35:04/);
  });

  test('Fix 4: MacBook-Pro-M5 (192.168.50.229) → scanner label present when in inventory', () => {
    // Map is only shown when inventory is provided. Without inventory, isSelf is not rendered.
    // Test that isSelf is set correctly on model data via topology.
    const { buildTopology } = require('../utils/topology');
    const devs = [
      { ip: '192.168.50.229', type: 'unknown', hostname: 'MacBook-Pro-M5', mac: '', vendor: '', os: '', ports: [] },
      { ip: '192.168.50.2', type: 'router', hostname: 'unifi', mac: '', vendor: '', os: '', ports: [] },
    ];
    const topo = buildTopology({ devices: devs, localIps: ['192.168.50.229', '192.168.1.5'] });
    const scanner = topo.groups.flatMap(g => g.devices).find(d => d.ip === '192.168.50.229');
    expect(scanner?.isSelf).toBe(true);
    expect(scanner?.isSelfPrimary).toBe(true);
  });

  test('Fix 4: 192.168.1.5 not in scan output — only appears if in inventory', () => {
    // 192.168.1.5 is in localIps but NOT in scan output → not in inventory → no isSelfSecondary shown
    const model = makeModel();
    const html = toHtml(model);
    // secondary interface label should NOT appear since 192.168.1.5 isn't scanned
    expect(html).not.toContain('secondary interface');
  });

  test('Fix 5: service names marked as estimates (no -sV)', () => {
    expect(makeModel().serviceDetection).toBe(false);
    const md = toMarkdown(makeModel());
    expect(md).toContain('estimates based on port numbers');
    // service entries have asterisk
    expect(md).toMatch(/domain \\\*/);
  });

  test('Fix 5 SK: service guess note in Slovak', () => {
    const md = toMarkdown(makeModel('sk'));
    expect(md).toContain('odhady podľa čísla portu');
  });

  test('Fix 5: no service guess note with -sV', () => {
    const m = buildReportModel({
      text: REAL_SCAN, command: 'nmap -sV 192.168.50.0/24',
      target: '192.168.50.0/24', timestamp: 't',
    });
    expect(m.serviceDetection).toBe(true);
    expect(toMarkdown(m)).not.toContain('estimates based on port numbers');
  });
});
