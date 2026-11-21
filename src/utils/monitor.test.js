import {
  normalizeMonitor, loadMonitor, saveMonitor, startMonitor, monitorDue, markRun, monitorChanges, MONITOR_INTERVALS,
} from './monitor';

const base = { args: ['-sV', '192.168.1.0/24'], command: 'nmap -sV 192.168.1.0/24', target: '192.168.1.0/24' };
const mem = () => { const m = {}; return { getItem: (k) => m[k] ?? null, setItem: (k, v) => { m[k] = v; }, removeItem: (k) => { delete m[k]; } }; };

test('startMonitor schedules the first repeat after the interval', () => {
  const m = startMonitor({ ...base, intervalMin: 15 }, 1000);
  expect(m).toMatchObject({ intervalMin: 15, lastRun: 1000, nextRun: 1000 + 15 * 60000, runs: 0 });
});

test('due only when time passed and no scan is running', () => {
  const m = startMonitor({ ...base, intervalMin: 60 }, 0);
  expect(monitorDue(m, 59 * 60000)).toBe(false);
  expect(monitorDue(m, 60 * 60000)).toBe(true);
  expect(monitorDue(m, 60 * 60000, true)).toBe(false);
  expect(monitorDue(null, 1e12)).toBe(false);
});

test('markRun moves the next run from now (no catch-up after sleep)', () => {
  const m = markRun(startMonitor({ ...base, intervalMin: 15 }, 0), 5 * 3600000);
  expect(m).toMatchObject({ runs: 1, lastRun: 5 * 3600000, nextRun: 5 * 3600000 + 15 * 60000 });
});

test('normalize rejects broken data and unknown intervals fall back to 1 hour', () => {
  expect(normalizeMonitor(null)).toBeNull();
  expect(normalizeMonitor({ ...base, args: [] })).toBeNull();
  expect(normalizeMonitor({ ...base, args: [1, 2] })).toBeNull();
  expect(normalizeMonitor({ ...base, target: ' ' })).toBeNull();
  expect(normalizeMonitor({ ...base, intervalMin: 7 }).intervalMin).toBe(60);
  expect(MONITOR_INTERVALS).toContain(1440);
});

test('storage round trip, stop removes it, broken storage does not throw', () => {
  const st = mem();
  const m = startMonitor({ ...base, intervalMin: 360 }, 1);
  saveMonitor(m, st);
  expect(loadMonitor(st)).toEqual(m);
  saveMonitor(null, st);
  expect(loadMonitor(st)).toBeNull();
  expect(loadMonitor({ getItem: () => '{x' })).toBeNull();
  expect(() => saveMonitor(m, { setItem: () => { throw new Error('full'); } })).not.toThrow();
});

test('alert on new findings, ports or hosts; not on fixes alone', () => {
  const d = { newFindings: [], openedPorts: [], newHosts: [], resolvedFindings: [1], closedPorts: [1, 2] };
  expect(monitorChanges(d)).toEqual({ alert: false, counts: { findings: 0, ports: 0, hosts: 0, fixed: 1, closed: 2 } });
  expect(monitorChanges({ ...d, openedPorts: [1] }).alert).toBe(true);
  expect(monitorChanges({ ...d, newHosts: [1] }).alert).toBe(true);
  expect(monitorChanges(null).alert).toBe(false);
});

test('last result is one of the known values, counts are sanitised', () => {
  const m = normalizeMonitor({ ...base, lastResult: 'changes', lastCounts: { ports: 2, hosts: -1, x: 5 } });
  expect(m.lastResult).toBe('changes');
  expect(m.lastCounts).toEqual({ findings: 0, ports: 2, hosts: 0, fixed: 0, closed: 0 });
  expect(normalizeMonitor({ ...base, lastResult: '<b>x</b>' }).lastResult).toBe('');
});
