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
