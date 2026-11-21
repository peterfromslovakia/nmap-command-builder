import { buildTopology, deviceRisk, hostIp } from './topology';

const dev = (ip, type, ports = [], extra = {}) => ({ ip, type, hostname: '', mac: '', vendor: '', ports: ports.map((port) => ({ port, proto: 'tcp', service: '' })), ...extra });

test('hostIp handles "name (ip)" and bare ip', () => {
  expect(hostIp('fileserver.lan (192.168.1.20)')).toBe('192.168.1.20');
  expect(hostIp('10.0.0.5')).toBe('10.0.0.5');
});

test('risk from worst finding, exploited flag, then risky ports', () => {
  const f = [{ host: 'x (10.0.0.5)', severity: 'medium' }, { host: '10.0.0.5', severity: 'critical', exploited: true }, { host: '10.0.0.6', severity: 'low' }];
  expect(deviceRisk(dev('10.0.0.5', 'windows'), f)).toMatchObject({ level: 'critical', findings: 2, exploited: true });
  expect(deviceRisk(dev('10.0.0.7', 'windows', [445, 80]), f)).toMatchObject({ level: 'exposed', riskyPorts: [445] });
  expect(deviceRisk(dev('10.0.0.8', 'linux', [443]), f).level).toBe('ok');
});

test('system gateway wins; groups ordered; self marked', () => {
  const devices = [dev('192.168.1.1', 'router'), dev('192.168.1.2', 'router'), dev('192.168.1.30', 'windows'),
    dev('192.168.1.10', 'windows'), dev('192.168.1.50', 'printer'), dev('192.168.1.5', 'firewall')];
  const t = buildTopology({ devices, gatewayIp: '192.168.1.2', localIps: ['192.168.1.30'] });
  expect(t.gateway.ip).toBe('192.168.1.2');
  expect(t.groups.map((g) => g.type)).toEqual(['firewall', 'windows', 'printer', 'router']);
  expect(t.groups[1].devices.map((d) => d.ip)).toEqual(['192.168.1.10', '192.168.1.30']);
  expect(t.groups[1].devices[1].isSelf).toBe(true);
  expect(t.total).toBe(6);
});

test('fallbacks: router .1, synthetic gateway in same /24, none for other subnet', () => {
  expect(buildTopology({ devices: [dev('10.0.0.9', 'router'), dev('10.0.0.1', 'router')] }).gateway.ip).toBe('10.0.0.1');
  const s = buildTopology({ devices: [dev('10.0.0.9', 'linux')], gatewayIp: '10.0.0.1' });
  expect(s.gateway).toMatchObject({ ip: '10.0.0.1', synthetic: true });
  expect(buildTopology({ devices: [dev('10.0.0.9', 'linux')], gatewayIp: '192.168.1.1' }).gateway).toBeNull();
});

test('segments: one frame for a /22 office network, one per range when several are scanned', () => {
  const { targetNetworks } = require('./topology');
  expect(targetNetworks('10.0.0.0/22 192.168.5.0/24, 10.1.1.1')).toEqual([
    { cidr: '10.0.0.0/22', net: 167772160, size: 1024 }, { cidr: '192.168.5.0/24', net: 3232236800, size: 256 }]);
  const devices = [dev('10.0.0.1', 'firewall'), dev('10.0.0.20', 'windows'), dev('10.0.3.200', 'windows'), dev('192.168.5.9', 'printer'), dev('172.16.0.4', 'linux')];
  const one = buildTopology({ devices: devices.slice(0, 3), gatewayIp: '10.0.0.1', target: '10.0.0.0/22' });
  expect(one.gateway.type).toBe('firewall');
  expect(one.segments).toHaveLength(1);
  expect(one.segments[0]).toMatchObject({ label: '10.0.0.0/22', total: 2 });
  const many = buildTopology({ devices, gatewayIp: '10.0.0.1', target: '10.0.0.0/22 192.168.5.0/24' });
  expect(many.segments.map((x) => [x.label, x.total, Boolean(x.other)])).toEqual([['10.0.0.0/22', 2, false], ['192.168.5.0/24', 1, false], ['', 1, true]]);
});
