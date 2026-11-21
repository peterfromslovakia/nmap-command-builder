const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  validateElevatedArgs, which, elevationMethod, askpassScript, writeAskpass, elevatedCommand, explainElevationError,
} = require('./elevate');

test('elevated runs forbid file input/output and script paths', () => {
  assert.strictEqual(validateElevatedArgs(['-sS', '-O', '-T4', '10.0.0.0/22']), null);
  assert.strictEqual(validateElevatedArgs(['-sS', '--script', 'vuln,smb-vuln-ms17-010', 'x']), null);
  assert.match(validateElevatedArgs(['-sS', '-oN', '/etc/sudoers', 'x']), /-oN is not allowed/);
  assert.match(validateElevatedArgs(['-sS', '-oX', 'out.xml', 'x']), /-oX/);
  assert.match(validateElevatedArgs(['-sS', '-iL', '/etc/shadow']), /-iL/);
  assert.match(validateElevatedArgs(['--script', 'evil.nse', 'x']), /only script names/);
  assert.match(validateElevatedArgs(['--script', 'x', '--script-args', 'userdb=/etc/shadow', 'y']), /file paths/);
  assert.strictEqual(validateElevatedArgs(['--script', 'vulners', '--script-args', 'mincvss=7.0', 'y']), null);
});

test('which returns absolute paths only', () => {
  const exists = (p) => p === '/opt/homebrew/bin/nmap';
  assert.strictEqual(which('nmap', 'relative/bin:/usr/bin:/opt/homebrew/bin', exists), '/opt/homebrew/bin/nmap');
  assert.strictEqual(which('nmap', 'relative/bin', () => true), null);
});

test('elevation method per platform', () => {
  const has = (...names) => (n) => (names.includes(n) ? `/usr/bin/${n}` : null);
  assert.deepStrictEqual(elevationMethod('darwin', has('sudo')), { method: 'sudo-askpass', helper: 'osascript' });
  assert.deepStrictEqual(elevationMethod('linux', has('sudo', 'zenity', 'pkexec')), { method: 'sudo-askpass', helper: 'zenity' });
  assert.deepStrictEqual(elevationMethod('linux', has('sudo', 'kdialog')), { method: 'sudo-askpass', helper: 'kdialog' });
  assert.deepStrictEqual(elevationMethod('linux', has('sudo', 'pkexec')), { method: 'pkexec' });
  assert.strictEqual(elevationMethod('linux', has()), null);
  assert.strictEqual(elevationMethod('win32', has('sudo')), null);
});

test('sudo command: askpass, empty prompt, -- before absolute nmap', () => {
  const c = elevatedCommand({ method: 'sudo-askpass', nmapPath: '/opt/homebrew/bin/nmap', args: ['-sS', 'x'], askpass: '/a/askpass.sh', prompt: 'P', env: { PATH: '/bin' } });
  assert.deepStrictEqual(c.args, ['-A', '-p', '', '--', '/opt/homebrew/bin/nmap', '-sS', 'x']);
  assert.strictEqual(c.cmd, 'sudo');
  assert.deepStrictEqual(c.env, { PATH: '/bin', SUDO_ASKPASS: '/a/askpass.sh', NCB_PROMPT: 'P' });
  assert.deepStrictEqual(elevatedCommand({ method: 'pkexec', nmapPath: '/usr/bin/nmap', args: ['-O', 'x'], env: {} }).args, ['/usr/bin/nmap', '-O', 'x']);
  assert.throws(() => elevatedCommand({ method: 'sudo-askpass', nmapPath: 'nmap', args: [] }), /nmap not found/);
});

test('askpass script is private and never contains the prompt text itself', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncb-askpass-'));
  const f = writeAskpass(dir, 'osascript');
  assert.strictEqual(fs.statSync(f).mode & 0o777, 0o700);
  const body = fs.readFileSync(f, 'utf8');
  assert.match(body, /with hidden answer/);
  assert.match(body, /system attribute "NCB_PROMPT"/);
  assert.match(askpassScript('zenity'), /--password/);
  assert.throws(() => askpassScript('xterm'), /Unknown/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('sudo / pkexec errors are explained', () => {
  assert.match(explainElevationError('peto is not in the sudoers file.'), /not an administrator/);
  assert.match(explainElevationError('sudo: no password was provided'), /not entered/);
  assert.match(explainElevationError('sudo: 3 incorrect password attempts'), /not entered/);
  assert.strictEqual(explainElevationError('Starting Nmap'), null);
  assert.match(explainElevationError('sudo: no password was provided', 'sk'), /Heslo správcu nebolo zadané/);
});
