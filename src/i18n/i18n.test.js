import { PORT_FIXES, FINDING_RULES, GENERIC_VULN_FIX, CVE_FIX } from '../data/remediation';
import { getPortIntel } from '../data/portIntel';
import SK from './sk';
import { tr, LABELS } from './report';

const dataStrings = () => {
  const set = new Set();
  Object.values(PORT_FIXES).flat().forEach((s) => set.add(s));
  FINDING_RULES.forEach((r) => { set.add(r.title); r.fix.forEach((s) => set.add(s)); });
  [...GENERIC_VULN_FIX, ...CVE_FIX].forEach((s) => set.add(s));
  for (let p = 1; p < 65536; p++) {
    const i = getPortIntel(p);
    if (i?.risk) set.add(i.risk);
  }
  return [...set];
};

test('every remediation / port text has a Slovak translation', () => {
  const missing = dataStrings().filter((s) => !Object.prototype.hasOwnProperty.call(SK, s));
  expect(missing).toEqual([]);
});

test('no unused translations (keeps the dictionary in sync with the data)', () => {
  const used = new Set(dataStrings());
  expect(Object.keys(SK).filter((k) => !used.has(k))).toEqual([]);
});

test('translations keep commands and config values unchanged', () => {
  // Technicke retazce (prikazy, direktivy) musia ostat v preklade doslova.
  const tokens = /(PermitRootLogin no|anonymous_enable=NO|Set-SmbServerConfiguration -EnableSMB1Protocol \$false|bind-address = 127\.0\.0\.1|MS17-010|CVE-\d{4}-\d+|TLS 1\.2\+|port 445|\d{3,4})/g;
  Object.entries(SK).forEach(([en, sk]) => {
    (en.match(tokens) || []).forEach((t) => expect([en, sk.includes(t)]).toEqual([en, true]));
  });
});

test('dynamic titles are translated, unknown text is kept', () => {
  expect(tr('1 known CVE for this service version (max CVSS 5)', 'sk')).toBe('1 známa CVE pre túto verziu služby (max. CVSS 5)');
  expect(tr('3 known CVEs for this service version (max CVSS 9.8)', 'sk')).toBe('3 známe CVE pre túto verziu služby (max. CVSS 9.8)');
  expect(tr('12 known CVEs for this service version (max CVSS 7)', 'sk')).toBe('12 známych CVE pre túto verziu služby (max. CVSS 7)');
  expect(tr('smb-vuln-x: vulnerable', 'sk')).toBe('smb-vuln-x: zraniteľné');
  expect(tr('Some nmap output', 'sk')).toBe('Some nmap output');
  expect(tr('Anonymous FTP login allowed', 'en')).toBe('Anonymous FTP login allowed');
});

test('both languages define the same labels', () => {
  const keys = (o) => Object.keys(o).sort();
  expect(keys(LABELS.sk)).toEqual(keys(LABELS.en));
  ['sev', 'riskText', 'changeTitles'].forEach((k) => expect(keys(LABELS.sk[k])).toEqual(keys(LABELS.en[k])));
});
