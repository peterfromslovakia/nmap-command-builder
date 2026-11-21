const test = require('node:test');
const assert = require('node:assert');
const { detectNetworks } = require('./network');

const mk = (address, netmask, extra = {}) => ({
  family: 'IPv4', internal: false, address, netmask, ...extra,
});

test('detects 192.168.50.0/24 from a Wi-Fi interface', () => {
  const r = detectNetworks({
    lo0: [mk('127.0.0.1', '255.0.0.0', { internal: true })],
    en0: [mk('192.168.50.23', '255.255.255.0'), { family: 'IPv6', internal: false, address: 'fe80::1', netmask: 'ffff:ffff:ffff:ffff::' }],
  });
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].cidr, '192.168.50.0/24');
  assert.strictEqual(r[0].suggested, '192.168.50.0/24');
  assert.strictEqual(r[0].iface, 'en0');
});

test('narrows huge networks to /24 around own address', () => {
  const r = detectNetworks({ en0: [mk('10.20.30.40', '255.0.0.0')] });
  assert.strictEqual(r[0].cidr, '10.0.0.0/8');
  assert.strictEqual(r[0].suggested, '10.20.30.0/24');
});

test('ignores link-local, loopback and broken masks', () => {
  const r = detectNetworks({
    en1: [mk('169.254.10.1', '255.255.0.0')],
    en2: [mk('192.168.1.5', '255.0.255.0')],
  });
  assert.strictEqual(r.length, 0);
});

test('prefers private non-virtual interfaces', () => {
  const r = detectNetworks({
    utun3: [mk('10.8.0.2', '255.255.255.0')],
    en0: [mk('192.168.50.23', '255.255.255.0')],
    en5: [mk('203.0.113.9', '255.255.255.0')],
  });
  assert.deepStrictEqual(r.map((x) => x.iface), ['en0', 'utun3', 'en5']);
});
