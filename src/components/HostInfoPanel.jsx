import React, { useMemo } from 'react';

/**
 * Parse single-host details from nmap output lines.
 * Returns null if no host found.
 */
function parseHostInfo(lines) {
  let ip = null, hostname = null, mac = null, vendor = null, latency = null;
  let hostCount = 0;

  for (const line of lines) {
    const sublines = (line.text || '').split('\n');
    for (const t of sublines) {
      // "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
      const hostMatch = t.match(/Nmap scan report for (\S+)(?:\s+\(([^)]+)\))?/i);
      if (hostMatch) {
        hostCount++;
        if (hostCount === 1) {
          const hasParens = !!hostMatch[2];
          if (hasParens) {
            hostname = hostMatch[1];
            ip = hostMatch[2];
          } else {
            ip = hostMatch[1];
            hostname = null;
          }
        }
      }

      // "Host is up (0.0032s latency)." or "Host is up."
      const latencyMatch = t.match(/Host is up\s*(?:\(([^)]*latency)\))?/i);
      if (latencyMatch && latency === null) {
        latency = latencyMatch[1] ? latencyMatch[1].replace(/\s*latency/, '').trim() : null;
      }

      // "MAC Address: 00:11:22:33:44:55 (Vendor Name)"
      const macMatch = t.match(/MAC Address:\s+([0-9A-Fa-f:]{17})(?:\s+\(([^)]*)\))?/i);
      if (macMatch && !mac) {
        mac = macMatch[1];
        vendor = macMatch[2] || null;
      }
    }
  }

  // Only return data if exactly 1 host was found (multi-host → HostDiscoveryPanel handles it)
  if (ip === null || hostCount !== 1) return null;
  return { ip, hostname, mac, vendor, latency };
}

export default function HostInfoPanel({ lines, scanStatus }) {
  const info = useMemo(() => parseHostInfo(lines), [lines]);

  if (scanStatus !== 'done' && scanStatus !== 'killed') return null;
  if (!info) return null;

  return (
    <div className="hostinfo-panel">
      <div className="hostinfo-panel__header">
        <span className="hostinfo-panel__title">HOST INFO</span>
        <span className="hostinfo-panel__ip">{info.ip}</span>
      </div>
      <div className="hostinfo-panel__body">
        <div className="hostinfo-row">
          <span className="hostinfo-label">IP</span>
          <span className="hostinfo-value hostinfo-value--ip">{info.ip}</span>
        </div>
        <div className="hostinfo-row">
          <span className="hostinfo-label">HOSTNAME</span>
          <span className="hostinfo-value">{info.hostname || '—'}</span>
        </div>
        <div className="hostinfo-row">
          <span className="hostinfo-label">MAC</span>
          <span className="hostinfo-value hostinfo-value--mac">{info.mac || '—'}</span>
        </div>
        <div className="hostinfo-row">
          <span className="hostinfo-label">VENDOR</span>
          <span className="hostinfo-value">{info.vendor || '—'}</span>
        </div>
        <div className="hostinfo-row">
          <span className="hostinfo-label">LATENCY</span>
          <span className="hostinfo-value hostinfo-value--latency">
            {info.latency ? info.latency : '—'}
          </span>
        </div>
      </div>
    </div>
  );
}
