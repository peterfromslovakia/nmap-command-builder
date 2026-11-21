import { validateTarget, validateFlagValue, sanitizeArg } from './validator';

describe('validateTarget', () => {
  test.each([
    '192.168.1.0/24',
    '10.0.0.1',
    '10.0.0.1-50',
    'scanme.nmap.org',
    '192.168.1.*',
    '10.0.0.0/8,example.com',
  ])('accepts %s', (t) => {
    expect(validateTarget(t).valid).toBe(true);
  });

  test.each([
    '192.168.1.0/33',
    '300.1.1.1',
    '10.0.0.50-10',
    '10.0.0.1-300',
    'a;b',
    '$(id)',
    '-iL',
    'a b',
  ])('rejects %s', (t) => {
    expect(validateTarget(t).valid).toBe(false);
  });
});

describe('validateFlagValue', () => {
  const text = { name: 'x', type: 'text', flag: '--exclude' };
  test('keeps slashes in values (paths, CIDR)', () => {
    expect(validateFlagValue(text, '10.0.0.0/8').valid).toBe(true);
    expect(sanitizeArg('/path/targets.txt')).toBe('/path/targets.txt');
  });
  test('rejects values that look like another flag', () => {
    expect(validateFlagValue(text, '--datadir').valid).toBe(false);
  });
  test('enforces number range', () => {
    const num = { name: 'n', type: 'number', flag: '--top-ports', min: 1, max: 100 };
    expect(validateFlagValue(num, '101').valid).toBe(false);
    expect(validateFlagValue(num, '50').valid).toBe(true);
  });
});
