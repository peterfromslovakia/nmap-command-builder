import { detectScanType, isDiscoveryScan, isVulnScan, arePortsComparable, areVulnsComparable, getPortSpec, hasVulnScripts, splitArgs } from './scanMeta';

describe('detectScanType', () => {
  test('discovery: -sn', () => {
    expect(detectScanType('nmap -sn 192.168.1.0/24')).toBe('discovery');
  });
  test('discovery: -sP (starý príznak)', () => {
    expect(detectScanType('nmap -sP 192.168.1.0/24')).toBe('discovery');
  });
  test('vuln: --script vuln', () => {
    expect(detectScanType('nmap -sV --script vuln 192.168.1.1')).toBe('vuln');
  });
  test('vuln: --script vuln,vulners', () => {
    expect(detectScanType('nmap --script vuln,vulners 192.168.1.1')).toBe('vuln');
  });
  test('service: -sV', () => {
    expect(detectScanType('nmap -sV 192.168.1.0/24')).toBe('service');
  });
  test('service: -A', () => {
    expect(detectScanType('nmap -A -T4 192.168.1.0/24')).toBe('service');
  });
  test('service: -sC', () => {
    expect(detectScanType('nmap -sC 192.168.1.1')).toBe('service');
  });
  test('port: základný sken', () => {
    expect(detectScanType('nmap 192.168.1.0/24')).toBe('port');
  });
  test('port: -sS bez verzií', () => {
    expect(detectScanType('nmap -sS -p- 192.168.1.1')).toBe('port');
  });
  test('prázdny príkaz → port', () => {
    expect(detectScanType('')).toBe('port');
    expect(detectScanType(null)).toBe('port');
  });
});

describe('isDiscoveryScan', () => {
  test('true pre -sn', () => expect(isDiscoveryScan('nmap -sn 192.168.1.0/24')).toBe(true));
  test('false pre -sV', () => expect(isDiscoveryScan('nmap -sV 192.168.1.1')).toBe(false));
});

describe('isVulnScan', () => {
  test('true pre --script vuln', () => expect(isVulnScan('nmap --script vuln 192.168.1.1')).toBe(true));
  test('false pre -sV', () => expect(isVulnScan('nmap -sV 192.168.1.1')).toBe(false));
});

describe('arePortsComparable', () => {
  test('false ak jeden sken je discovery', () => {
    expect(arePortsComparable('nmap -sn 192.168.1.0/24', 'nmap -sV 192.168.1.0/24')).toBe(false);
    expect(arePortsComparable('nmap -sV 192.168.1.0/24', 'nmap -sn 192.168.1.0/24')).toBe(false);
    expect(arePortsComparable('nmap -sn 192.168.1.0/24', 'nmap -sn 192.168.1.0/24')).toBe(false);
  });
  test('true ak oba skeny testujú porty', () => {
    expect(arePortsComparable('nmap -sV 192.168.1.0/24', 'nmap -sV 192.168.1.0/24')).toBe(true);
    expect(arePortsComparable('nmap 192.168.1.0/24', 'nmap -A 192.168.1.0/24')).toBe(true);
  });
});

describe('areVulnsComparable', () => {
  test('false ak jeden sken je discovery', () => {
    expect(areVulnsComparable('nmap -sn 192.168.1.0/24', 'nmap -sV 192.168.1.0/24')).toBe(false);
  });
  test('false ak jeden sken má vuln skripty a druhý nie', () => {
    expect(areVulnsComparable('nmap -sV 192.168.1.1', 'nmap --script vuln 192.168.1.1')).toBe(false);
    expect(areVulnsComparable('nmap --script vuln 192.168.1.1', 'nmap -sV 192.168.1.1')).toBe(false);
  });
  test('true ak oba nemajú NSE skripty', () => {
    expect(areVulnsComparable('nmap -sV 192.168.1.0/24', 'nmap -sV 192.168.1.0/24')).toBe(true);
    expect(areVulnsComparable('nmap 192.168.1.1', 'nmap -sV 192.168.1.1')).toBe(true);
  });
  test('true ak oba majú vuln skripty', () => {
    expect(areVulnsComparable('nmap --script vuln 192.168.1.1', 'nmap --script vuln 192.168.1.1')).toBe(true);
  });
  test('false ak jeden sken mal -sC/-A a druhý len -sV', () => {
    // -sC spúšťa NSE skripty; -sV bez skriptov → nálezy z NSE mohli zmiznúť len preto,
    // že neboli testované, nie že boli opravené.
    expect(areVulnsComparable('nmap -sS -sC 192.168.1.1', 'nmap -sS -sV 192.168.1.1')).toBe(false);
    expect(areVulnsComparable('nmap -sV 192.168.1.1', 'nmap -sC 192.168.1.1')).toBe(false);
    expect(areVulnsComparable('nmap -A 192.168.1.1', 'nmap -sV 192.168.1.1')).toBe(false);
    expect(areVulnsComparable('nmap 192.168.1.1', 'nmap -A 192.168.1.1')).toBe(false);
  });
  test('true ak oba mali -sC alebo oba mali -A', () => {
    expect(areVulnsComparable('nmap -sC 192.168.1.1', 'nmap -sC 192.168.1.1')).toBe(true);
    expect(areVulnsComparable('nmap -A 192.168.1.1', 'nmap -A -T4 192.168.1.1')).toBe(true);
  });
});

describe('getPortSpec', () => {
  test('default keď nie je -p ani -F', () => {
    expect(getPortSpec('nmap -sV 192.168.1.1')).toBe('default');
  });
  test('all pre -p-', () => {
    expect(getPortSpec('nmap -p- 192.168.1.1')).toBe('all');
  });
  test('fast pre -F', () => {
    expect(getPortSpec('nmap -F 192.168.1.1')).toBe('fast');
  });
  test('explicitný port range pre -p', () => {
    expect(getPortSpec('nmap -p 80,443 192.168.1.1')).toBe('80,443');
    expect(getPortSpec('nmap -p 1-1000 192.168.1.1')).toBe('1-1000');
  });
  test('topN pre --top-ports', () => {
    expect(getPortSpec('nmap --top-ports 100 192.168.1.1')).toBe('top100');
  });
});

describe('--flag=value normalization (splitArgs)', () => {
  test('splitArgs normalizuje --script=vuln na --script vuln', () => {
    expect(splitArgs('nmap --script=vuln 192.168.1.1')).toContain('--script');
    const a = splitArgs('nmap --script=vuln 192.168.1.1');
    expect(a[a.indexOf('--script') + 1]).toBe('vuln');
  });

  test('detectScanType rozpozná --script=vuln ako vuln sken', () => {
    expect(detectScanType('nmap --script=vuln 192.168.1.1')).toBe('vuln');
    expect(detectScanType('nmap -sV --script=vuln,vulners 192.168.1.1')).toBe('vuln');
  });

  test('detectScanType rozpozná -sn aj s inými --flag=value', () => {
    expect(detectScanType('nmap -sn --max-rtt-timeout=100ms 192.168.1.0/24')).toBe('discovery');
  });

  test('hasVulnScripts rozpozná --script=safe', () => {
    expect(hasVulnScripts('nmap --script=safe 192.168.1.1')).toBe(true);
    expect(hasVulnScripts('nmap --script=http-title 192.168.1.1')).toBe(false);
  });

  test('getPortSpec rozpozná --top-ports=100', () => {
    expect(getPortSpec('nmap --top-ports=100 192.168.1.1')).toBe('top100');
  });
});

describe('areVulnsComparable — rôzne explicit script sety', () => {
  test('false ak oba majú --script ale s rôznymi hodnotami', () => {
    expect(areVulnsComparable(
      'nmap -sV --script vuln,ftp-anon 192.168.1.1',
      'nmap -sV --script vuln 192.168.1.1',
    )).toBe(false);
  });

  test('false ak --script=value formát s rôznymi hodnotami', () => {
    expect(areVulnsComparable(
      'nmap --script=vuln,ftp-anon 192.168.1.1',
      'nmap --script=vuln 192.168.1.1',
    )).toBe(false);
  });

  test('true ak oba majú rovnaké --script hodnoty', () => {
    expect(areVulnsComparable(
      'nmap -sV --script vuln 192.168.1.1',
      'nmap -sV --script vuln 192.168.1.1',
    )).toBe(true);
  });

  test('true ak len jeden má --script a druhý používa -sC (rôzne typy → false cez vuln check)', () => {
    // -sC → hasVulnScripts=true, --script vuln → hasVulnScripts=true, ale typy sa líšia
    // t1=service (-sC), t2=vuln (--script vuln) → oneHasVuln=true, t1!==t2 → false
    expect(areVulnsComparable(
      'nmap -sC 192.168.1.1',
      'nmap --script=vuln 192.168.1.1',
    )).toBe(false);
  });

  test('true ak ani jeden nemá --script (oba service)', () => {
    expect(areVulnsComparable(
      'nmap -sV -sC 192.168.1.1',
      'nmap -A 192.168.1.1',
    )).toBe(true);
  });
});
