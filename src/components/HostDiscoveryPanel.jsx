import React, { useMemo } from 'react';

function parseHosts(lines) {
  const hosts = [];
  let current = null;

  for (const line of lines) {
    const text = line.text || '';

    // "Nmap scan report for 192.168.1.1"
    // "Nmap scan report for hostname (192.168.1.1)"
    const hostMatch = text.match(/Nmap scan report for (\S+)(?:\s+\(([^)]+)\))?/i);
    if (hostMatch) {
      if (current) hosts.push(current);
      const hasParens = !!hostMatch[2];
      current = {
        ip: hasParens ? hostMatch[2] : hostMatch[1],
        hostname: hasParens ? hostMatch[1] : null,
        mac: null,
        vendor: null,
      };
    }

    // "MAC Address: 00:11:22:33:44:55 (Vendor Name)"
    const macMatch = text.match(/MAC Address:\s+([0-9A-Fa-f:]{17})(?:\s+\(([^)]*)\))?/i);
    if (macMatch && current) {
      current.mac = macMatch[1];
      current.vendor = macMatch[2] || null;
    }
  }

  if (current) hosts.push(current);
  return hosts;
}

export default function HostDiscoveryPanel({ lines, scanStatus }) {
  const hosts = useMemo(() => parseHosts(lines), [lines]);

  if ((scanStatus !== 'done' && scanStatus !== 'killed') || hosts.length < 2) return null;

  return (
    <div className="hosts-panel">
      <div className="hosts-panel__header">
        <span className="hosts-panel__title">DISCOVERED HOSTS</span>
        <span className="hosts-panel__count">{hosts.length} host{hosts.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="hosts-panel__body">
        <table className="hosts-table">
          <thead>
            <tr>
              <th className="hosts-th">IP ADDRESS</th>
              <th className="hosts-th">HOSTNAME</th>
              <th className="hosts-th">MAC</th>
              <th className="hosts-th">VENDOR</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, i) => (
              <tr key={i} className="hosts-row">
                <td className="hosts-cell hosts-cell--ip">{h.ip}</td>
                <td className="hosts-cell hosts-cell--hostname">{h.hostname || '—'}</td>
                <td className="hosts-cell hosts-cell--mac">{h.mac || '—'}</td>
                <td className="hosts-cell hosts-cell--vendor">{h.vendor || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
