const test = require('node:test');
const assert = require('node:assert');
const { validateArgs } = require('./argsValidator');

test('accepts whitelisted flags and script names', () => {
  assert.strictEqual(validateArgs(['-sV', '-T4', '--script', 'vuln,vulners', '-p', '22,80', '10.0.0.1']), null);
  assert.strictEqual(validateArgs(['-PS22,80', '10.0.0.0/24']), null);
});

test('rejects unknown flags', () => {
  assert.match(validateArgs(['--datadir', '/tmp']), /not allowed/);
  assert.match(validateArgs(['--script-args-file', 'x']), /not allowed/);
});

test('rejects script paths', () => {
  assert.match(validateArgs(['--script', '/tmp/evil.nse']), /script names/);
  assert.match(validateArgs(['--script', '../x']), /script names/);
});

test('rejects control characters and empty input', () => {
  assert.ok(validateArgs(['-sV', 'a\nb']));
  assert.ok(validateArgs([]));
});
