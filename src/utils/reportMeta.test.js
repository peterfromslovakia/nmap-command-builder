import { loadReportMeta, saveReportMeta } from './reportMeta';

const mem = () => {
  const m = {};
  return { getItem: (k) => m[k] ?? null, setItem: (k, v) => { m[k] = v; } };
};

test('defaults: English, nothing filled in, remember on', () => {
  expect(loadReportMeta(mem())).toEqual({ lang: 'en', tester: '', organization: '', client: '', authorization: '', remember: true, saved: false });
  expect(loadReportMeta(null).lang).toBe('en');
});

test('remembers details between reports', () => {
  const st = mem();
  saveReportMeta({ lang: 'sk', tester: ' Ján ', organization: 'ACME', client: '', authorization: 'A-1', remember: true }, st);
  expect(loadReportMeta(st)).toEqual({ lang: 'sk', tester: 'Ján', organization: 'ACME', client: '', authorization: 'A-1', remember: true, saved: true });
});

test('"do not remember" keeps only the language and wipes personal details', () => {
  const st = mem();
  saveReportMeta({ lang: 'sk', tester: 'Ján', remember: true }, st);
  saveReportMeta({ lang: 'sk', tester: 'Ján', remember: false }, st);
  expect(loadReportMeta(st)).toMatchObject({ lang: 'sk', tester: '', remember: false });
});
