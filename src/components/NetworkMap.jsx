import React, { useMemo } from 'react';

function parseHostsFromLines(lines) {
  const hosts = [];
  for (const line of lines) {
    const sublines = (line.text || '').split('\n');
    for (const text of sublines) {
      const m = text.match(/Nmap scan report for (\S+)(?:\s+\(([^)]+)\))?/i);
      if (m) {
        const hasParens = !!m[2];
        hosts.push({
          ip: hasParens ? m[2] : m[1],
          hostname: hasParens ? m[1] : null,
        });
      }
    }
  }
  return hosts;
}

function guessHostType(ip, hostname) {
  if (hostname) {
    const h = hostname.toLowerCase();
    if (/router|gw|gateway/.test(h)) return 'router';
    if (/firewall|fw/.test(h)) return 'firewall';
    if (/\b(server|srv|web|db|sql|mail|ns\d*|dc\d*|ldap|proxy|nas)\b/.test(h)) return 'server';
    if (/\b(pc|desktop|laptop|workstation|ws|wks|client|win|mac|ubuntu|debian)\b/.test(h)) return 'workstation';
  }
  const last = parseInt(ip.split('.').pop() || '0', 10);
  if (last === 1 || last === 254) return 'router';
  if (last === 2 || last === 253) return 'gateway';
  if (last >= 100 && last <= 200) return 'workstation';
  return 'host';
}

const TYPE_ICONS = { router: '⬡', gateway: '⬡', firewall: '⛨', server: '▣', workstation: '▢', host: '◉' };
const TYPE_CSS   = { router: 'node--router', gateway: 'node--gateway', firewall: 'node--firewall', server: 'node--server', workstation: 'node--workstation', host: 'node--host' };

export default function NetworkMap({ lines, scanStatus, scannedTarget }) {
  const hosts = useMemo(() => parseHostsFromLines(lines), [lines]);

  const isCidr = /\/\d+$/.test(scannedTarget);
  if ((scanStatus !== 'done' && scanStatus !== 'killed') || !isCidr || hosts.length < 2) return null;

  return (
    <div className="netmap">
      <div className="netmap__header">
        <span className="netmap__title">NETWORK MAP</span>
        <span className="netmap__subnet">{scannedTarget}</span>
        <span className="netmap__count">{hosts.length} hosts</span>
      </div>
      <div className="netmap__body">
        {hosts.map((h, i) => {
          const type = guessHostType(h.ip, h.hostname);
          return (
            <div key={i} className={`netmap-node ${TYPE_CSS[type]}`} title={`${h.ip}${h.hostname ? ' · ' + h.hostname : ''} · ${type}`}>
              <span className="netmap-node__icon">{TYPE_ICONS[type]}</span>
              <span className="netmap-node__ip">{h.ip}</span>
              {h.hostname && (
                <span className="netmap-node__hostname">{h.hostname}</span>
              )}
              <span className="netmap-node__type">{type}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
