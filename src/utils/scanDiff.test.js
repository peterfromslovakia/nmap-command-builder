import {
  makeSnapshot, diffScans, hostKey, comparisonFor, loadSnapshots, saveSnapshot, clearSnapshots, baselinesFor, MAX_SNAPSHOTS,
} from './scanDiff';

const OLD = `Nmap scan report for fileserver.lan (192.168.1.20)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    Apache httpd 2.4.41
Nmap scan report for 192.168.1.30
PORT   STATE SERVICE
80/tcp open  http
`;

const NEW = `Nmap scan report for nas.lan (192.168.1.20)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1
80/tcp   open  http    Apache httpd 2.4.41
3306/tcp open  mysql   MySQL 5.7.33
Nmap scan report for 192.168.1.40
PORT    STATE SERVICE
443/tcp open  https
`;

const snap = (id, time, text, command = 'nmap -sV 192.168.1.0/24') =>
  makeSnapshot({ id, time, target: ' 192.168.1.0/24 ', command, text });

const a = snap(1, '2026-11-20T10:00:00Z', OLD);
const b = snap(2, '2026-11-21T10:00:00Z', NEW);
const d = diffScans(a, b);

test('hostKey prefers the IP address', () => {
  expect(hostKey('nas.lan (192.168.1.20)')).toBe('192.168.1.20');
  expect(hostKey('192.168.1.40')).toBe('192.168.1.40');
});

test('snapshot is compact and trims the target', () => {
  expect(a.target).toBe('192.168.1.0/24');
  expect(a.hosts[0].ports).toHaveLength(3);
  expect(a.findings.map((f) => f.id)).toEqual(['ftp-anon']);
  expect(JSON.stringify(a)).not.toContain('Nmap scan report');
});

test('detects new and gone hosts (renamed host matched by IP)', () => {
  expect(d.newHosts.map((h) => h.host)).toEqual(['192.168.1.40']);
  expect(d.goneHosts.map((h) => h.host)).toEqual(['192.168.1.30']);
});

test('detects opened / closed ports and version changes', () => {
  expect(d.openedPorts.map((p) => p.port)).toEqual(['3306']);
  expect(d.closedPorts.map((p) => p.port)).toEqual(['21']);
  expect(d.changedVersions).toEqual([
    expect.objectContaining({ port: '22', from: 'OpenSSH 8.2p1', to: 'OpenSSH 9.6p1' }),
  ]);
});

test('finding on a host that is still up counts as resolved', () => {
  expect(d.resolvedFindings.map((f) => f.id)).toEqual(['ftp-anon']);
  expect(d.newFindings).toEqual([]);
  expect(d.total).toBe(6);
  expect(d.sameCommand).toBe(true);
});

test('identical scans have no differences; different commands are flagged', () => {
  const same = diffScans(a, snap(3, '2026-11-22T00:00:00Z', OLD, 'nmap -p- 192.168.1.0/24'));
  expect(same.total).toBe(0);
  expect(same.sameCommand).toBe(false);
});

describe('snapshot storage', () => {
  const mem = () => {
    const m = {};
    return { getItem: (k) => m[k] ?? null, setItem: (k, v) => { m[k] = v; }, removeItem: (k) => { delete m[k]; } };
  };

  test('saves newest first, deduplicates and caps the list', () => {
    const st = mem();
    for (let i = 0; i < MAX_SNAPSHOTS + 5; i++) saveSnapshot({ id: i, target: 't', time: String(i) }, st);
    saveSnapshot({ id: 34, target: 't', time: '34' }, st);
    const list = loadSnapshots(st);
    expect(list).toHaveLength(MAX_SNAPSHOTS);
    expect(list[0].id).toBe(34);
    expect(list.filter((s) => s.id === 34)).toHaveLength(1);
    expect(clearSnapshots(st)).toEqual([]);
    expect(loadSnapshots(st)).toEqual([]);
  });

  test('broken or unavailable storage does not throw', () => {
    expect(loadSnapshots({ getItem: () => '{broken' })).toEqual([]);
    expect(loadSnapshots({ getItem: () => { throw new Error('denied'); } })).toEqual([]);
    expect(() => saveSnapshot({ id: 1 }, { getItem: () => null, setItem: () => { throw new Error('full'); } })).not.toThrow();
  });

  test('baselinesFor returns older scans of the same target only', () => {
    const list = [b, a, snap(9, '2026-11-19T00:00:00Z', OLD), { ...a, id: 7, target: '10.0.0.1' }];
    expect(baselinesFor(list, b).map((s) => s.id)).toEqual([1, 9]);
  });
});

test('comparisonFor picks the chosen baseline, falls back to the newest', () => {
  const c = snap(3, '2026-11-22T00:00:00Z', NEW);
  const list = [c, b, a];
  expect(comparisonFor(list, c).baseline.id).toBe(2);
  expect(comparisonFor(list, c, 1).baseline.id).toBe(1);
  expect(comparisonFor(list, c, 999).baseline.id).toBe(2);
  expect(comparisonFor([a], a)).toBeNull();
  expect(comparisonFor(list, null)).toBeNull();
});

describe('discovery scan vs port scan diff', () => {
  // Discovery sken našiel len 192.168.1.20; 192.168.1.30 nebolo dostupné
  const SN_OUTPUT = `Nmap scan report for fileserver.lan (192.168.1.20)
`;
  const snapSn = (id, time) =>
    makeSnapshot({ id, time, target: '192.168.1.0/24', command: 'nmap -sn 192.168.1.0/24', text: SN_OUTPUT });
  const snapFull = (id, time) =>
    makeSnapshot({ id, time, target: '192.168.1.0/24', command: 'nmap -sV 192.168.1.0/24', text: OLD });

  test('snapshot ukladá scanType', () => {
    expect(snapSn(1, '2026-11-20T10:00:00Z').scanType).toBe('discovery');
    expect(snapFull(1, '2026-11-20T10:00:00Z').scanType).toBe('service');
  });

  test('snapshot ukladá exitCode a signal', () => {
    const s = makeSnapshot({ id: 1, time: '2026-11-20T10:00:00Z', target: '192.168.1.0/24', command: 'nmap -sn 192.168.1.0/24', text: '', exitCode: 0, signal: null });
    expect(s.exitCode).toBe(0);
    expect(s.signal).toBeUndefined();
  });

  test('discovery vs port scan: žiadne closedPorts ani resolvedFindings', () => {
    const prev = snapFull(1, '2026-11-20T10:00:00Z'); // mal otvorené porty
    const curr = snapSn(2, '2026-11-21T10:00:00Z');   // discovery: žiadne porty
    const d = diffScans(prev, curr);
    expect(d.closedPorts).toEqual([]);
    expect(d.resolvedFindings).toEqual([]);
    expect(d.portsComparable).toBe(false);
    expect(d.methodDiffers).toBe(true);
  });

  test('discovery vs port scan: noví/stratení hostitelia sa stále detegujú', () => {
    const prev = snapFull(1, '2026-11-20T10:00:00Z');
    const curr = snapSn(2, '2026-11-21T10:00:00Z');
    const d = diffScans(prev, curr);
    // 192.168.1.30 bol v prev, ale nie v curr (SN výstup ho neobsahuje)
    expect(d.goneHosts.map((h) => h.host)).toContain('192.168.1.30');
  });

  test('rovnaké port skeny: closedPorts a resolvedFindings fungujú normálne', () => {
    const prev = snapFull(1, '2026-11-20T10:00:00Z');
    // Porovnanie pomocou NEW výstupu
    const currNew = makeSnapshot({ id: 2, time: '2026-11-21T10:00:00Z', target: '192.168.1.0/24', command: 'nmap -sV 192.168.1.0/24', text: NEW });
    const d = diffScans(prev, currNew);
    expect(d.portsComparable).toBe(true);
    expect(d.methodDiffers).toBe(false);
    expect(d.closedPorts.map((p) => p.port)).toContain('21');
    expect(d.resolvedFindings.map((f) => f.id)).toContain('ftp-anon');
  });
});

describe('port range diff', () => {
  const snapSpec = (id, portFlag) =>
    makeSnapshot({ id, time: `2026-11-2${id}T10:00:00Z`, target: '192.168.1.1', command: `nmap -sV ${portFlag} 192.168.1.1`, text: OLD });

  test('rovnaký port spec → portRangeDiffers false', () => {
    const d = diffScans(snapSpec(1, '-p 80,443'), snapSpec(2, '-p 80,443'));
    expect(d.portRangeDiffers).toBe(false);
    expect(d.methodDiffers).toBe(false);
  });

  test('rôzny port spec → portRangeDiffers true + methodDiffers true', () => {
    const d = diffScans(snapSpec(1, '-p-'), snapSpec(2, '-p 80,443'));
    expect(d.portRangeDiffers).toBe(true);
    expect(d.methodDiffers).toBe(true);
  });

  test('default vs default → portRangeDiffers false', () => {
    const a = makeSnapshot({ id: 1, time: '2026-11-20T10:00:00Z', target: '192.168.1.1', command: 'nmap -sV 192.168.1.1', text: OLD });
    const b = makeSnapshot({ id: 2, time: '2026-11-21T10:00:00Z', target: '192.168.1.1', command: 'nmap -sV 192.168.1.1', text: NEW });
    expect(diffScans(a, b).portRangeDiffers).toBe(false);
  });

  test('snapshot ukladá portSpec', () => {
    expect(snapSpec(1, '-p-').portSpec).toBe('all');
    expect(snapSpec(1, '-p 80,443').portSpec).toBe('80,443');
    expect(makeSnapshot({ id: 1, time: '2026-11-20T10:00:00Z', target: 't', command: 'nmap -sV 192.168.1.1', text: '' }).portSpec).toBe('default');
  });
});

describe('port state accuracy (F-001)', () => {
  const mkSnap = (id, text, portFlag = '') =>
    makeSnapshot({ id, time: `2026-11-2${id}T10:00:00Z`, target: '192.168.1.1',
      command: `nmap -sV${portFlag ? ' ' + portFlag : ''} 192.168.1.1`, text });

  const PREV_OPEN = `Nmap scan report for 192.168.1.1
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2
80/tcp  open  http    Apache 2.4
443/tcp open  https   nginx 1.18
`;

  test('open → filtered: classified as filteredPorts, not closedPorts', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT    STATE    SERVICE VERSION
22/tcp  open     ssh     OpenSSH 8.2
80/tcp  filtered http
443/tcp open     https   nginx 1.18
`;
    const prev = mkSnap(1, PREV_OPEN);
    const d = diffScans(prev, mkSnap(2, curr));
    expect(d.filteredPorts.map((p) => p.port)).toContain('80');
    expect(d.closedPorts.map((p) => p.port)).not.toContain('80');
  });

  test('open → closed|filtered: classified as filteredPorts', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT    STATE           SERVICE VERSION
22/tcp  open            ssh     OpenSSH 8.2
80/tcp  closed|filtered http
443/tcp open            https   nginx 1.18
`;
    const prev = mkSnap(1, PREV_OPEN);
    const d = diffScans(prev, mkSnap(2, curr));
    expect(d.filteredPorts.map((p) => p.port)).toContain('80');
    expect(d.closedPorts.map((p) => p.port)).not.toContain('80');
  });

  test('open → closed (explicitly shown): classified as closedPorts', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 8.2
80/tcp  closed http
443/tcp open   https   nginx 1.18
`;
    const prev = mkSnap(1, PREV_OPEN);
    const d = diffScans(prev, mkSnap(2, curr));
    expect(d.closedPorts.map((p) => p.port)).toContain('80');
    expect(d.filteredPorts.map((p) => p.port)).not.toContain('80');
  });

  test('open → not in curr output, same port spec → closedPorts (nmap suppresses closed)', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2
443/tcp open  https   nginx 1.18
`;
    // Port 80 simply absent (closed by default, nmap didn't show it)
    const prev = mkSnap(1, PREV_OPEN);
    const d = diffScans(prev, mkSnap(2, curr));
    expect(d.closedPorts.map((p) => p.port)).toContain('80');
    expect(d.notTestedPorts.map((p) => p.port)).not.toContain('80');
  });

  test('open → not in curr, different port spec → notTestedPorts', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT    STATE SERVICE
22/tcp  open  ssh
`;
    // prev scanned all ports (found 22, 80, 443); curr only scanned -p 22
    const prev = mkSnap(1, PREV_OPEN, '-p-');
    const d = diffScans(prev, mkSnap(2, curr, '-p 22'));
    expect(d.notTestedPorts.map((p) => p.port)).toContain('80');
    expect(d.notTestedPorts.map((p) => p.port)).toContain('443');
    expect(d.closedPorts.map((p) => p.port)).not.toContain('80');
  });

  test('snapshot stores allPortStates including filtered', () => {
    const text = `Nmap scan report for 192.168.1.1
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  filtered http
443/tcp closed   https
`;
    const snap = mkSnap(1, text);
    const states = snap.allPortStates?.['192.168.1.1'];
    expect(states?.['22/tcp']).toBe('open');
    expect(states?.['80/tcp']).toBe('filtered');
    expect(states?.['443/tcp']).toBe('closed');
  });

  test('filteredPorts and notTestedPorts included in total', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  filtered http
`;
    const prev = mkSnap(1, PREV_OPEN, '-p-');
    const d = diffScans(prev, mkSnap(2, curr, '-p 22,80'));
    expect(d.total).toBe(d.openedPorts.length + d.closedPorts.length + d.filteredPorts.length +
      d.notTestedPorts.length + d.changedVersions.length + d.newFindings.length +
      d.resolvedFindings.length + d.newHosts.length + d.goneHosts.length);
  });

  test('killed scan (exitCode≠0): absent port → notTestedPorts, not closedPorts', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
22/tcp open  ssh
`;
    const prev = mkSnap(1, PREV_OPEN);
    const currSnap = makeSnapshot({ id: 2, time: '2026-11-22T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sV 192.168.1.1', text: curr, exitCode: 1, signal: null });
    const d = diffScans(prev, currSnap);
    expect(d.scanIncomplete).toBe(true);
    expect(d.notTestedPorts.map(p => p.port)).toContain('80');
    expect(d.notTestedPorts.map(p => p.port)).toContain('443');
    expect(d.closedPorts).toHaveLength(0);
  });

  test('signal-killed scan: absent port → notTestedPorts', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
22/tcp open  ssh
`;
    const prev = mkSnap(1, PREV_OPEN);
    const currSnap = makeSnapshot({ id: 2, time: '2026-11-22T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sV 192.168.1.1', text: curr, exitCode: null, signal: 'SIGTERM' });
    const d = diffScans(prev, currSnap);
    expect(d.scanIncomplete).toBe(true);
    expect(d.notTestedPorts.map(p => p.port)).toContain('80');
    expect(d.closedPorts).toHaveLength(0);
  });

  test('--open flag: absent port → notTestedPorts (cannot distinguish filtered vs closed)', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
22/tcp open  ssh
`;
    const prev = mkSnap(1, PREV_OPEN);
    const currSnap = makeSnapshot({ id: 2, time: '2026-11-22T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sV --open 192.168.1.1', text: curr });
    const d = diffScans(prev, currSnap);
    expect(d.scanIncomplete).toBe(true);
    expect(d.notTestedPorts.map(p => p.port)).toContain('80');
    expect(d.closedPorts).toHaveLength(0);
  });

  test('clean scan (exitCode=0, no --open): absent port → closedPorts', () => {
    const curr = `Nmap scan report for 192.168.1.1
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
`;
    const prev = mkSnap(1, PREV_OPEN);
    const currSnap = makeSnapshot({ id: 2, time: '2026-11-22T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sV 192.168.1.1', text: curr, exitCode: 0, signal: null });
    const d = diffScans(prev, currSnap);
    expect(d.scanIncomplete).toBe(false);
    expect(d.closedPorts.map(p => p.port)).toContain('80');
    expect(d.notTestedPorts).toHaveLength(0);
  });
});

describe('diffScans — areVulnsComparable with -sC vs -sV', () => {
  const textWithFinding = `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
`;
  const textNoFinding = `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
`;

  test('prev -sC finding NOT shown as resolved when curr only used -sV (methods differ)', () => {
    const prev = makeSnapshot({ id: 1, time: '2026-11-20T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sS -sC 192.168.1.1', text: textWithFinding });
    const curr = makeSnapshot({ id: 2, time: '2026-11-21T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sS -sV 192.168.1.1', text: textNoFinding });
    const d = diffScans(prev, curr);
    expect(d.vulnsComparable).toBe(false);
    expect(d.methodDiffers).toBe(true);
    expect(d.resolvedFindings).toHaveLength(0);
  });

  test('prev -sC finding IS shown as resolved when curr also used -sC and finding gone', () => {
    const prev = makeSnapshot({ id: 1, time: '2026-11-20T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sS -sC 192.168.1.1', text: textWithFinding });
    const curr = makeSnapshot({ id: 2, time: '2026-11-21T10:00:00Z', target: '192.168.1.1',
      command: 'nmap -sS -sC 192.168.1.1', text: textNoFinding });
    const d = diffScans(prev, curr);
    expect(d.vulnsComparable).toBe(true);
    expect(d.resolvedFindings).toHaveLength(1);
    expect(d.resolvedFindings[0].id).toBe('ftp-anon');
  });
});
