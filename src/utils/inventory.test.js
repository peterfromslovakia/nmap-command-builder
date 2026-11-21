import {
  parseInventory, mergeArp, classifyDevice, buildInventory, inventoryCsv, ipNum, DISCOVERY_MODES, DEVICE_TYPES,
} from './inventory';
import { buildCommand } from './commandBuilder';
import { rootRequirements } from './privileges';

// eslint-disable-next-line global-require
const { validateArgs } = require('../../electron/argsValidator');

const OUT = `Starting Nmap 7.95
Nmap scan report for router.lan (10.0.0.1)
Host is up (0.0021s latency).
PORT    STATE SERVICE VERSION
53/tcp  open  domain  dnsmasq 2.89
80/tcp  open  http    lighttpd
MAC Address: 00:11:22:33:44:55 (Unknown)
Nmap scan report for 10.0.0.20
Host is up (0.012s latency).
PORT     STATE SERVICE
9100/tcp open  jetdirect
Nmap scan report for nas.lan (10.0.0.5)
Host is up (0.0009s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
5000/tcp open  http    nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap scan report for 10.0.0.31
Host is up.
Nmap scan report for DESKTOP-AB12.lan (10.0.0.100)
Host is up (0.004s latency).
PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
Service Info: OS: Windows; Device: general purpose
Nmap done: 5 IP addresses (5 hosts up) scanned in 9.1 seconds
`;

test('parseInventory: hosts, hostnames, latency, ports, service info', () => {
  const d = parseInventory(OUT);
  expect(d.map((x) => x.ip)).toEqual(['10.0.0.1', '10.0.0.20', '10.0.0.5', '10.0.0.31', '10.0.0.100']);
  expect(d[0]).toMatchObject({ hostname: 'router.lan', latencyMs: 2.1, mac: '00:11:22:33:44:55', vendor: '' });
  expect(d[0].ports.map((p) => p.port)).toEqual([53, 80]);
  expect(d[2]).toMatchObject({ os: 'Linux' });
  expect(d[3]).toMatchObject({ hostname: '', latencyMs: null, ports: [] });
  expect(d[4]).toMatchObject({ os: 'Windows', deviceHint: 'general purpose' });
});

test('mergeArp fills MAC / vendor only where nmap had none', () => {
  const d = mergeArp(parseInventory(OUT), [
    { ip: '10.0.0.1', mac: 'AA:AA:AA:AA:AA:AA', vendor: 'X' },
    { ip: '10.0.0.5', mac: '00:11:32:01:02:03', vendor: 'Synology Incorporated', randomized: false },
    { ip: '10.0.0.31', mac: '6E:00:00:00:00:01', vendor: null, randomized: true },
  ]);
  expect(d[0].mac).toBe('00:11:22:33:44:55');
  expect(d[2]).toMatchObject({ mac: '00:11:32:01:02:03', vendor: 'Synology Incorporated' });
  expect(d[3]).toMatchObject({ randomizedMac: true, vendor: '' });
});

test('device types from ports, vendor, name and OS', () => {
  const inv = buildInventory(OUT, [{ ip: '10.0.0.5', mac: '00:11:32:01:02:03', vendor: 'Synology Incorporated' }]);
  expect(Object.fromEntries(inv.map((d) => [d.ip, d.type]))).toEqual({
    '10.0.0.1': 'router', '10.0.0.5': 'nas', '10.0.0.20': 'printer', '10.0.0.31': 'unknown', '10.0.0.100': 'windows',
  });
  const dev = (o) => classifyDevice({ hostname: '', deviceHint: '', vendor: '', os: '', ports: [], ...o });
  const ports = (...p) => p.map((port) => ({ port, service: '', version: '' }));
  expect(dev({ ports: ports(62078) })).toBe('phone');
  expect(dev({ vendor: 'Hikvision Digital Technology' })).toBe('camera');
  expect(dev({ ports: ports(554) })).toBe('camera');
  expect(dev({ vendor: 'Apple, Inc.' })).toBe('apple');
  expect(dev({ hostname: 'opnsense.internal' })).toBe('firewall');
  expect(dev({ vendor: 'Espressif Inc.' })).toBe('iot');
  expect(dev({ ports: ports(22) })).toBe('linux');
  expect(dev({ ports: ports(3306) })).toBe('server');
  expect(dev({ vendor: 'Brother Industries' })).toBe('printer');
  // nmap "Device:" and the hostname win over the network card vendor
  expect(dev({ vendor: 'Ubiquiti Networks', deviceHint: 'router' })).toBe('router');
  expect(dev({ vendor: 'Ubiquiti Networks', hostname: 'router.lan' })).toBe('router');
  expect(dev({ vendor: 'Ubiquiti Networks' })).toBe('ap');
  expect(dev({ deviceHint: 'general purpose', ports: ports(445) })).toBe('windows');
  expect(dev({ deviceHint: 'WAP' })).toBe('ap');
  Object.keys(DEVICE_TYPES).forEach((k) => expect(DEVICE_TYPES[k].label).toBeTruthy());
});

test('inventory is sorted numerically by IP', () => {
  expect(buildInventory(OUT).map((d) => d.ip)).toEqual(['10.0.0.1', '10.0.0.5', '10.0.0.20', '10.0.0.31', '10.0.0.100']);
  expect(ipNum('10.0.0.2')).toBeLessThan(ipNum('10.0.0.10'));
  expect(ipNum('host.lan')).toBe(Number.MAX_SAFE_INTEGER);
});

test('CSV export: header, quoting and no spreadsheet formula injection', () => {
  const csv = inventoryCsv([{ ip: '10.0.0.9', hostname: '=HYPERLINK("x")', mac: '', vendor: 'A, B', type: 'server', os: '', ports: [{ port: 22, proto: 'tcp', service: 'ssh' }], latencyMs: 1.5 }]);
  const [head, row] = csv.split('\n');
  expect(head).toBe('IP,Hostname,MAC,Vendor,Type,OS,Open ports,Latency ms');
  expect(row).toBe('10.0.0.9,"\'=HYPERLINK(""x"")",,"A, B",Server,,22/tcp ssh,1.5');
});

test('discovery commands are accepted by the main-process whitelist and need no root', () => {
  Object.entries(DISCOVERY_MODES).forEach(([mode, { flags }]) => {
    const { args } = buildCommand('192.168.1.0/24', flags, false);
    expect([mode, validateArgs(args)]).toEqual([mode, null]);
    expect([mode, rootRequirements(flags)]).toEqual([mode, []]);
    expect(args.some((a) => a.startsWith('-PS'))).toBe(true);
  });
  expect(buildCommand('x', DISCOVERY_MODES.quick.flags, false).args).toContain('-sn');
  expect(buildCommand('x', DISCOVERY_MODES.standard.flags, false).args).toEqual(expect.arrayContaining(['-F', '-sV', '--version-light']));
});
