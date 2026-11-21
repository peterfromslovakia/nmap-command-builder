import { adjustForNoRoot, describeChanges } from './privileges';
import { buildCommand } from './commandBuilder';
import { FLAG_MAP } from '../data/flags';
import { PRESETS } from '../data/presets';

const cmd = (flags) => buildCommand('192.168.1.10', adjustForNoRoot(flags).flags, true).command;

test('SYN scan becomes TCP connect scan', () => {
  expect(cmd({ ss: true, timing_template: '4' })).toBe('nmap -T4 -sT 192.168.1.10');
});

test('-A becomes -sV -sC, -O becomes -sV without duplicates', () => {
  expect(cmd({ aggressive: true, os_detect: true, osscan_guess: true })).toBe('nmap -sV -sC 192.168.1.10');
});

test('existing -sT / -sV are kept, not duplicated', () => {
  expect(cmd({ ss: true, st: true, sv: true, os_detect: true })).toBe('nmap -sT -sV 192.168.1.10');
});

test('flags without equivalent are removed and explained', () => {
  const { flags, changes } = adjustForNoRoot({ su: true, traceroute: true, decoy: 'RND:5', sv: true });
  expect(flags).toEqual({ sv: true });
  expect(changes.map((c) => c.from)).toEqual(['-sU', '--traceroute', '-D']);
  expect(changes.every((c) => c.kind === 'removed' && c.note)).toBe(true);
  expect(describeChanges(changes)).toContain('-sU removed: UDP scanning is not possible without root');
});

test('nothing changes for scans that do not need root', () => {
  const sel = { sv: true, sc: true, port_range: '22,80', timing_template: '4' };
  expect(adjustForNoRoot(sel)).toEqual({ flags: sel, changes: [] });
});

test('every flag that requires root is handled', () => {
  const rootFlags = Object.values(FLAG_MAP).filter((f) => f.requiresRoot).map((f) => f.id);
  rootFlags.forEach((id) => {
    const value = FLAG_MAP[id].type === 'boolean' ? true : '1';
    const { flags, changes } = adjustForNoRoot({ [id]: value });
    expect(flags[id]).toBeUndefined();
    expect(changes).toHaveLength(1);
  });
});

test('after adjustment no preset needs root', () => {
  PRESETS.forEach((p) => {
    const { requiresRoot } = buildCommand('10.0.0.1', adjustForNoRoot(p.flags).flags, true);
    expect(requiresRoot).toBe(false);
  });
});
