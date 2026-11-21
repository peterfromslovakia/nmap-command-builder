import { parseFindings, splitScriptBlocks } from './findings';
import { getPortFixes } from '../data/remediation';

const SAMPLE = `Starting Nmap 7.95
Nmap scan report for 192.168.1.10
Host is up (0.0010s latency).
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0            4096 Jan 01 00:00 pub
22/tcp  open  ssh          OpenSSH 8.2p1
| vulners:
|   cpe:/a:openbsd:openssh:8.2p1:
|       CVE-2023-38408  9.8  https://vulners.com/cve/CVE-2023-38408
|       CVE-2020-15778  6.8  https://vulners.com/cve/CVE-2020-15778
|_      PACKETSTORM:173661  9.8  https://vulners.com/packetstorm/PACKETSTORM:173661
443/tcp open  https
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL library.
|     State: VULNERABLE
|     Risk factor: High
|     IDs:  CVE:CVE-2014-0160
|_      http://cvedetails.com/cve/2014-0160/
445/tcp open  microsoft-ds
Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|_    Risk factor: HIGH
| smb-vuln-foo:
|   VULNERABLE:
|   Some Unknown Bug
|     State: LIKELY VULNERABLE
|_    IDs:  CVE:CVE-2099-12345
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
`;

describe('splitScriptBlocks', () => {
  test('tracks host and port context', () => {
    const blocks = splitScriptBlocks(SAMPLE);
    const names = blocks.map((b) => `${b.script}@${b.port || 'host'}`);
    expect(names).toEqual([
      'ftp-anon@21/tcp',
      'vulners@22/tcp',
      'ssl-heartbleed@443/tcp',
      'smb-vuln-ms17-010@host',
      'smb-vuln-foo@host',
      'smb2-security-mode@host',
    ]);
    expect(blocks[0].host).toBe('192.168.1.10');
  });
});

describe('parseFindings', () => {
  const findings = parseFindings(SAMPLE);
  const ids = findings.map((f) => f.id);

  test('detects known findings', () => {
    expect(ids).toEqual(expect.arrayContaining([
      'ftp-anon', 'vulners', 'heartbleed', 'ms17-010', 'smb-signing', 'generic:smb-vuln-foo',
    ]));
    expect(findings).toHaveLength(6);
  });

  test('sorted by severity, critical first', () => {
    expect(findings[0].severity).toBe('critical');
    expect(findings[findings.length - 1].severity).toBe('medium');
  });

  test('vulners summarises CVEs and ignores non-CVE ids', () => {
    const v = findings.find((f) => f.id === 'vulners');
    expect(v.severity).toBe('critical');
    expect(v.evidence).toBe('CVE-2023-38408 (9.8), CVE-2020-15778 (6.8)');
    expect(v.port).toBe('22/tcp');
  });

  test('generic finding uses title and CVE from output', () => {
    const g = findings.find((f) => f.id === 'generic:smb-vuln-foo');
    expect(g.title).toBe('Some Unknown Bug');
    expect(g.refs[0]).toContain('CVE-2099-12345');
  });

  test('requires VULNERABLE state for CVE-based rules', () => {
    const notVuln = `| ssl-heartbleed:\n|_  CVE-2014-0160 mentioned but not vulnerable\n`;
    expect(parseFindings(notVuln)).toEqual([]);
  });

  test('every finding has fix steps', () => {
    findings.forEach((f) => expect(f.fix.length).toBeGreaterThan(0));
  });
});

test('getPortFixes', () => {
  expect(getPortFixes('445').length).toBeGreaterThan(0);
  expect(getPortFixes(12345)).toEqual([]);
});
