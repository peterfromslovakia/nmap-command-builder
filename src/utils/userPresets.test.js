import {
  sanitizeFlags, loadUserPresets, saveUserPreset, deleteUserPreset, MAX_USER_PRESETS, MAX_NAME,
} from './userPresets';

const mem = (init) => {
  const m = init ? { 'ncb.userPresets.v1': init } : {};
  return { getItem: (k) => m[k] ?? null, setItem: (k, v) => { m[k] = v; } };
};

test('sanitizeFlags keeps only known flags with safe values', () => {
  expect(sanitizeFlags({
    sv: true, timing_template: '4', bogus: true, sc: false, ports: '', script: 'a\nb', __proto__: { x: 1 },
  })).toEqual({ sv: true, timing_template: '4' });
  expect(sanitizeFlags(null)).toEqual({});
});

test('save, load, overwrite by name (case-insensitive) and delete', () => {
  const st = mem();
  const t0 = new Date('2026-11-21T10:00:00Z');
  expect(saveUserPreset({ name: ' Weekly NAS ', flags: { sv: true }, target: ' 192.168.1.20 ' }, st, t0).ok).toBe(true);
  let r = saveUserPreset({ name: 'weekly nas', flags: { sv: true, sc: true } }, st, new Date(t0.getTime() + 1));
  expect(r.ok).toBe(true);
  expect(r.list).toHaveLength(1);
  expect(r.list[0]).toMatchObject({ name: 'weekly nas', flags: { sv: true, sc: true }, target: '' });

  r = saveUserPreset({ name: 'SYN', flags: { ss: true } }, st, new Date(t0.getTime() + 2));
  const loaded = loadUserPresets(st);
  expect(loaded.map((p) => p.name)).toEqual(['SYN', 'weekly nas']);
  expect(loaded[0].requiresRoot).toBe(true);
  expect(loaded[1].requiresRoot).toBe(false);

  expect(deleteUserPreset(loaded[0].id, st).map((p) => p.name)).toEqual(['weekly nas']);
});

test('rejects empty name, empty flags and too many presets; trims long names', () => {
  const st = mem();
  expect(saveUserPreset({ name: '  ', flags: { sv: true } }, st).error).toMatch(/name/i);
  expect(saveUserPreset({ name: 'x', flags: { nope: true } }, st).error).toMatch(/flag/i);
  expect(saveUserPreset({ name: 'y'.repeat(200), flags: { sv: true } }, st).list[0].name).toHaveLength(MAX_NAME);
  for (let i = 1; i < MAX_USER_PRESETS; i++) saveUserPreset({ name: `p${i}`, flags: { sv: true } }, st, new Date(i));
  expect(loadUserPresets(st)).toHaveLength(MAX_USER_PRESETS);
  expect(saveUserPreset({ name: 'one more', flags: { sv: true } }, st).ok).toBe(false);
  expect(saveUserPreset({ name: 'p3', flags: { sc: true } }, st).ok).toBe(true); // prepis existujuceho je OK
});

test('tampered or broken storage is cleaned up, never throws', () => {
  const st = mem(JSON.stringify([
    { id: 'a', name: 'ok', flags: { sv: true, evil: '--interactive' } },
    { id: 'b', name: '', flags: { sv: true } },
    'garbage',
    { id: 'c', name: 'no flags', flags: {} },
  ]));
  expect(loadUserPresets(st)).toEqual([expect.objectContaining({ id: 'a', flags: { sv: true } })]);
  expect(loadUserPresets(mem('{broken'))).toEqual([]);
  expect(loadUserPresets({ getItem: () => { throw new Error('denied'); } })).toEqual([]);
  expect(loadUserPresets(null)).toEqual([]);
});
