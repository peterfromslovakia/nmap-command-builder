const test = require('node:test');
const assert = require('node:assert');
const { parseMacRoute, parseProcRoute, parseWinRoute } = require('./gateway');

test('macOS route -n get default', () => {
  assert.strictEqual(parseMacRoute('   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n'), '192.168.1.1');
  assert.strictEqual(parseMacRoute('route: writing to routing socket: not in table'), null);
  assert.strictEqual(parseMacRoute('    gateway: fe80::1%en0'), null);
});

test('Linux /proc/net/route', () => {
  const t = 'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n'
    + 'eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n'
    + 'eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n';
  assert.strictEqual(parseProcRoute(t), '192.168.1.1');
  assert.strictEqual(parseProcRoute('Iface\tDestination\tGateway\n'), null);
});

test('Windows route print (lowest metric wins)', () => {
  const t = 'IPv4 Route Table\r\nActive Routes:\r\nNetwork Destination        Netmask          Gateway       Interface  Metric\r\n'
    + '          0.0.0.0          0.0.0.0      10.0.0.1      10.0.0.20     50\r\n'
    + '          0.0.0.0          0.0.0.0   192.168.1.1   192.168.1.15     25\r\n';
  assert.strictEqual(parseWinRoute(t), '192.168.1.1');
  assert.strictEqual(parseWinRoute('Active Routes:\r\nNone\r\n'), null);
});
