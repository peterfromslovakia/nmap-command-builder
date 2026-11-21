import { PRESETS } from './presets';
import { FLAG_MAP } from './flags';
import { NSE_SCRIPT_MAP, DANGEROUS_CATEGORIES } from './nseScripts';
import { buildCommand } from '../utils/commandBuilder';
import { parseList } from '../utils/nseSelection';
const { validateArgs } = require('../../electron/argsValidator');

const RISK_RANK = { low: 0, medium: 1, high: 2 };

// Najvyssie riziko skriptov v presete (podla katalogu NSE skriptov).
function scriptRisk(preset) {
  let rank = 0;
  for (const name of parseList(preset.flags.script)) {
    if (DANGEROUS_CATEGORIES.has(name)) rank = Math.max(rank, 3);
    else if (name === 'vuln' || name === 'intrusive') rank = Math.max(rank, 2);
    const s = NSE_SCRIPT_MAP[name];
    if (s?.risk === 'dangerous') rank = Math.max(rank, 3);
    else if (s?.risk === 'intrusive') rank = Math.max(rank, 1);
  }
  return rank; // 0 safe, 1 intrusive, 2 vuln/intrusive category, 3 dangerous
}

describe.each(PRESETS.map((p) => [p.id, p]))('preset %s', (_id, preset) => {
  test('has a valid risk level', () => {
    expect(Object.keys(RISK_RANK)).toContain(preset.risk);
  });

  test('uses only known flags', () => {
    Object.keys(preset.flags).forEach((f) => expect(FLAG_MAP[f]).toBeDefined());
  });

  test('produces args accepted by the main-process validator', () => {
    const { args } = buildCommand('192.168.1.10', preset.flags, !preset.safe);
    expect(validateArgs(args)).toBeNull();
    // ziadny flag presetu sa nesmie potichu zahodit
    Object.keys(preset.flags).forEach((f) => {
      expect(args.some((a) => a.startsWith(FLAG_MAP[f].flag))).toBe(true);
    });
  });

  test('is marked risky enough for the scripts it runs', () => {
    const r = scriptRisk(preset);
    if (r >= 3) {
      expect(preset.risk).toBe('high');
      expect(preset.safe).toBe(false); // len v ADV mode
    } else if (r === 2) {
      expect(preset.risk).toBe('high');
    } else if (r === 1) {
      expect(RISK_RANK[preset.risk]).toBeGreaterThanOrEqual(RISK_RANK.medium);
    }
  });

  test('ADV-only flags make the preset ADV-only', () => {
    const advFlag = Object.keys(preset.flags).some((f) => FLAG_MAP[f].safe === false);
    if (advFlag) expect(preset.safe).toBe(false);
  });

  test('medium / high presets explain the risk', () => {
    if (preset.risk !== 'low') expect(preset.riskNote || preset.warning).toBeTruthy();
  });
});

test('preset ids are unique', () => {
  const ids = PRESETS.map((p) => p.id);
  expect(new Set(ids).size).toBe(ids.length);
});
