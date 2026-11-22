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

test('accepts valid --script-args values', () => {
  assert.strictEqual(validateArgs(['--script', 'vulners', '--script-args', 'mincvss=5.0', '10.0.0.1']), null);
  assert.strictEqual(validateArgs(['--script', 'http-enum', '--script-args', 'http.useragent=Mozilla 5.0', '10.0.0.1']), null);
  assert.strictEqual(validateArgs(['--script', 'vulners', '--script-args', 'vulners.showall=true,mincvss=4.0', '10.0.0.1']), null);
  // Lomka je povolená: user-agent strings a cesty k wordlistom sú legitímne NSE argumenty
  assert.strictEqual(validateArgs(['--script', 'http-enum', '--script-args', 'http.useragent=Mozilla/5.0', '10.0.0.1']), null);
  assert.strictEqual(validateArgs(['--script', 'brute', '--script-args', 'brute.db=/usr/share/wordlists/rockyou.txt', '10.0.0.1']), null);
});

test('rejects --script-args with shell injection chars', () => {
  // Backslash (Windows cesta) — blokovaný DANGEROUS regexom v nmap:run, tu nie, ale otestujme konzistenciu
  // Semicolon, pipe a iné shell metacharaktery sú blokované
  assert.match(validateArgs(['--script', 'brute', '--script-args', 'db=C:\\passwords.txt']), /key=value/);
  assert.match(validateArgs(['--script', 'http-brute', '--script-args', 'pass=test;id']), /key=value/);
});
