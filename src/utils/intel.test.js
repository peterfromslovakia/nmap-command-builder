import { collectCves, applyIntel, formatEpss } from './intel';

const F = [
  { id: 'vulners', title: 'CVEs', severity: 'medium', host: 'h', port: '22/tcp', cves: [{ id: 'CVE-2020-1', score: 6.5 }, { id: 'CVE-2021-2', score: 5 }] },
  { id: 'ms17-010', title: 'EternalBlue', severity: 'critical', host: 'h', cves: [{ id: 'CVE-2017-0143', score: null }] },
  { id: 'generic:x', title: 'x vulnerable', severity: 'high', host: 'h', cves: [{ id: 'CVE-2022-9', score: null }] },
  { id: 'ftp-anon', title: 'FTP', severity: 'high', host: 'h', cves: [] },
];
const INTEL = {
  kev: { 'CVE-2021-2': { dueDate: '2022-01-10', ransomware: true }, 'CVE-2017-0143': { dueDate: '2022-08-10', ransomware: true } },
  epss: { 'CVE-2020-1': { epss: 0.02, percentile: 0.8 }, 'CVE-2021-2': { epss: 0.71, percentile: 0.99 } },
  nvd: { 'CVE-2022-9': { score: 9.8, severity: 'critical' } },
};

test('collectCves', () => {
  expect(collectCves(F)).toEqual(['CVE-2020-1', 'CVE-2021-2', 'CVE-2017-0143', 'CVE-2022-9']);
  expect(collectCves([{ id: 'a' }])).toEqual([]);
});

test('actively exploited finding is escalated to at least HIGH and its CVE listed first', () => {
  const r = applyIntel(F, INTEL);
  const v = r.find((f) => f.id === 'vulners');
  expect(v).toMatchObject({ severity: 'high', originalSeverity: 'medium', escalated: true, exploited: true, ransomware: true, kevDue: '2022-01-10', epssMax: 0.71 });
  expect(v.cveDetails.map((c) => c.id)).toEqual(['CVE-2021-2', 'CVE-2020-1']);
});

test('critical stays critical; NVD score refines generic findings upwards only', () => {
  const r = applyIntel(F, INTEL);
  expect(r.find((f) => f.id === 'ms17-010')).toMatchObject({ severity: 'critical', escalated: false, exploited: true });
  expect(r.find((f) => f.id === 'generic:x')).toMatchObject({ severity: 'critical', escalated: true });
  expect(r.find((f) => f.id === 'generic:x').cveDetails[0].score).toBe(9.8);
});

test('order: severity, then actively exploited first', () => {
  const r = applyIntel(F, INTEL);
  expect(r.map((f) => f.id)).toEqual(['ms17-010', 'generic:x', 'vulners', 'ftp-anon']);
});

test('without intel nothing changes except added fields', () => {
  const r = applyIntel(F, null);
  expect(r.map((f) => f.severity)).toEqual(['critical', 'high', 'high', 'medium']);
  expect(r.every((f) => f.exploited === false && f.escalated === false)).toBe(true);
});

test('formatEpss', () => {
  expect(formatEpss(0.93307)).toBe('93 %');
  expect(formatEpss(0.0523)).toBe('5.2 %');
  expect(formatEpss(0.00041)).toBe('0.04 %');
  expect(formatEpss(null)).toBe('');
});
