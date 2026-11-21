import { rootRequirements, ROOT_FLAG_IDS } from './privileges';
import { FLAG_MAP } from '../data/flags';
import { PRESETS } from '../data/presets';

test('lists selected root-only flags with their effect', () => {
  const r = rootRequirements({ ss: true, sv: true, spoof_mac: '0', timing_template: '4' });
  expect(r.map((x) => [x.flag, x.effect])).toEqual([['-sS', 'quits'], ['--spoof-mac', 'ignored']]);
  expect(r[0].tip).toContain('-sT');
});

test('nothing listed for unprivileged scans', () => {
  expect(rootRequirements({ st: true, sv: true, sc: true, aggressive: true })).toEqual([]);
});

test('root list matches requiresRoot in flag definitions', () => {
  const marked = Object.values(FLAG_MAP).filter((f) => f.requiresRoot).map((f) => f.id).sort();
  expect([...ROOT_FLAG_IDS].sort()).toEqual(marked);
});

test('-A works without root (only OS detection / traceroute are skipped)', () => {
  expect(FLAG_MAP.aggressive.requiresRoot).toBeFalsy();
  expect(FLAG_MAP.aggressive.warning).toMatch(/root/i);
});

test('preset requiresRoot matches its flags', () => {
  PRESETS.forEach((p) => {
    expect([p.id, Boolean(p.requiresRoot)]).toEqual([p.id, rootRequirements(p.flags).length > 0]);
  });
});
