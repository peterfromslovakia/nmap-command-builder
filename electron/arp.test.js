const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const {
  normalizeMac, isRandomizedMac, parseArp, parseOui, lookupVendor, ouiCandidates,
} = require('./arp');

test('normalizeMac pads, uppercases and rejects broadcast / multicast / garbage', () => {
  assert.strictEqual(normalizeMac('c:ea:14:9:6:a8'), '0C:EA:14:09:06:A8');
  assert.strictEqual(normalizeMac('00-11-32-AB-CD-EF'), '00:11:32:AB:CD:EF');
  assert.strictEqual(normalizeMac('ff:ff:ff:ff:ff:ff'), null);
  assert.strictEqual(normalizeMac('01:00:5e:00:00:fb'), null);
  assert.strictEqual(normalizeMac('(incomplete)'), null);
  assert.strictEqual(normalizeMac('00:11:22:33:44'), null);
});

test('randomized (locally administered) MAC', () => {
  assert.strictEqual(isRandomizedMac('6E:63:F8:00:00:01'), true);
  assert.strictEqual(isRandomizedMac('00:11:32:00:00:01'), false);
});

test('parses macOS, Linux, Windows and /proc/net/arp formats', () => {
  const mac = `? (10.0.0.1) at 0:11:32:a:b:c on en0 ifscope [ethernet]
? (10.0.0.9) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (10.0.0.1) at 0:11:32:a:b:c on en10 ifscope [ethernet]`;
  assert.deepStrictEqual(parseArp(mac), [{ ip: '10.0.0.1', mac: '00:11:32:0A:0B:0C' }]);

  const linux = '? (192.168.7.2) at b8:27:eb:12:34:56 [ether] on eth0';
  assert.deepStrictEqual(parseArp(linux), [{ ip: '192.168.7.2', mac: 'B8:27:EB:12:34:56' }]);

  const win = `Interface: 192.168.7.10 --- 0x4
  Internet Address      Physical Address      Type
  192.168.7.1           00-11-32-aa-bb-cc     dynamic
  192.168.7.255         ff-ff-ff-ff-ff-ff     static`;
  assert.deepStrictEqual(parseArp(win), [{ ip: '192.168.7.1', mac: '00:11:32:AA:BB:CC' }]);

  const proc = `IP address       HW type     Flags       HW address            Mask     Device
192.168.7.3      0x1         0x2         00:11:d8:01:02:03     *        eth0
192.168.7.4      0x1         0x0         00:00:00:00:00:00     *        eth0`;
  assert.deepStrictEqual(parseArp(proc), [{ ip: '192.168.7.3', mac: '00:11:D8:01:02:03' }]);
});

test('vendor lookup uses the longest prefix and skips randomized MACs', () => {
  const oui = parseOui(`# comment
001132 Synology Incorporated
0050C2 IEEE Registration Authority
0050C2ABC Some Small Vendor
B827EB Raspberry Pi Foundation`);
  assert.strictEqual(lookupVendor('00:11:32:01:02:03', oui), 'Synology Incorporated');
  assert.strictEqual(lookupVendor('00:50:C2:AB:C1:23', oui), 'Some Small Vendor');
  assert.strictEqual(lookupVendor('00:50:C2:11:11:11', oui), 'IEEE Registration Authority');
  assert.strictEqual(lookupVendor('6E:63:F8:00:00:01', oui), null);
  assert.strictEqual(lookupVendor('AA:AA:AA:00:00:00', new Map()), null);
});

test('OUI database is looked up next to nmap on every platform', () => {
  const mac = ouiCandidates({ PATH: ['/opt/homebrew/bin', '/usr/bin'].join(path.delimiter) }, 'darwin');
  assert.ok(mac.includes(path.join('/opt/homebrew/bin', '..', 'share', 'nmap', 'nmap-mac-prefixes')));
  assert.ok(mac.includes('/usr/share/nmap/nmap-mac-prefixes'));
  assert.ok(ouiCandidates({ PATH: '' }, 'win32').includes('C:\\Program Files (x86)\\Nmap\\nmap-mac-prefixes'));
});
