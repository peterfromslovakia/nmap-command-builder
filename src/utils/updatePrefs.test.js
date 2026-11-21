import {
  loadUpdatePrefs, saveUpdatePrefs, shouldAutoCheck, shouldShowBanner, CHECK_INTERVAL_MS,
} from './updatePrefs';

const mem = () => {
  const m = {};
  return { getItem: (k) => m[k] ?? null, setItem: (k, v) => { m[k] = v; } };
};

test('defaults: automatic check on, never checked', () => {
  expect(loadUpdatePrefs(mem())).toEqual({ auto: true, lastCheck: 0, dismissed: '' });
  expect(loadUpdatePrefs(null)).toEqual({ auto: true, lastCheck: 0, dismissed: '' });
});

test('save / load roundtrip', () => {
  const st = mem();
  saveUpdatePrefs({ auto: false, lastCheck: 5, dismissed: '1.4.0' }, st);
  expect(loadUpdatePrefs(st)).toEqual({ auto: false, lastCheck: 5, dismissed: '1.4.0' });
});

test('checks at most every 12 hours and never when turned off', () => {
  const now = 10 * CHECK_INTERVAL_MS;
  expect(shouldAutoCheck({ auto: true, lastCheck: 0 }, now)).toBe(true);
  expect(shouldAutoCheck({ auto: true, lastCheck: now - 1000 }, now)).toBe(false);
  expect(shouldAutoCheck({ auto: true, lastCheck: now - CHECK_INTERVAL_MS }, now)).toBe(true);
  expect(shouldAutoCheck({ auto: true, lastCheck: now + 99999 }, now)).toBe(true); // posunute hodiny
  expect(shouldAutoCheck({ auto: false, lastCheck: 0 }, now)).toBe(false);
});

test('banner only for a new, not dismissed version', () => {
  const r = { ok: true, available: true, latest: '1.4.0' };
  expect(shouldShowBanner(r, { dismissed: '' })).toBe(true);
  expect(shouldShowBanner(r, { dismissed: '1.4.0' })).toBe(false);
  expect(shouldShowBanner({ ...r, latest: '1.5.0' }, { dismissed: '1.4.0' })).toBe(true);
  expect(shouldShowBanner({ ok: true, available: false }, { dismissed: '' })).toBe(false);
  expect(shouldShowBanner({ ok: false }, { dismissed: '' })).toBe(false);
  expect(shouldShowBanner(null, { dismissed: '' })).toBe(false);
});
