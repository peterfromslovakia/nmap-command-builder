import React, { useMemo, useState } from 'react';
import { parseScanSummary } from '../utils/commandBuilder';
import { getPortIntel } from '../data/portIntel';
import { getPortRisk } from '../data/portRisk';

/**
 * Collect intel entries for all open ports that have data.
 * Deduplicate by port number.
 */
function buildIntelEntries(openPorts) {
  const seen = new Set();
  const entries = [];

  for (const p of openPorts) {
    if (seen.has(p.port)) continue;
    const intel = getPortIntel(p.port);
    if (!intel) continue;
    seen.add(p.port);
    entries.push({ port: p.port, risk: getPortRisk(p.port), ...intel });
  }

  // Sort: high risk first, then medium, then safe
  const order = { high: 0, medium: 1, safe: 2 };
  return entries.sort((a, b) => (order[a.risk] || 2) - (order[b.risk] || 2));
}

const RISK_LABEL = { high: 'HIGH', medium: 'MED', safe: 'SAFE' };
const RISK_CSS   = { high: 'intel-risk--high', medium: 'intel-risk--medium', safe: 'intel-risk--safe' };

export default function IntelPanel({ lines, scanStatus }) {
  const { openPorts } = useMemo(() => parseScanSummary(lines), [lines]);
  const entries = useMemo(() => buildIntelEntries(openPorts), [openPorts]);

  const [expandedPorts, setExpandedPorts] = useState(new Set());

  const togglePort = (port) => {
    setExpandedPorts((prev) => {
      const next = new Set(prev);
      if (next.has(port)) {
        next.delete(port);
      } else {
        next.add(port);
      }
      return next;
    });
  };

  if (scanStatus !== 'done' && scanStatus !== 'killed') return null;
  if (entries.length === 0) return null;

  const highCount = entries.filter((e) => e.risk === 'high').length;
  const medCount  = entries.filter((e) => e.risk === 'medium').length;

  return (
    <div className="intel-panel">
      <div className="intel-panel__header">
        <span className="intel-panel__title">SECURITY INTEL</span>
        <div className="intel-panel__summary">
          {highCount > 0 && (
            <span className="intel-badge intel-badge--high">{highCount} HIGH</span>
          )}
          {medCount > 0 && (
            <span className="intel-badge intel-badge--medium">{medCount} MED</span>
          )}
        </div>
      </div>
      <div className="intel-panel__body">
        {entries.map((e) => {
          const isOpen = expandedPorts.has(e.port);
          return (
            <div key={e.port} className={`intel-entry intel-entry--${e.risk}`}>
              {/* Always-visible row — click to toggle */}
              <button
                className="intel-entry__row"
                onClick={() => togglePort(e.port)}
              >
                <span className={`intel-risk ${RISK_CSS[e.risk]}`}>{RISK_LABEL[e.risk]}</span>
                <span className="intel-port">{e.port}</span>
                <span className="intel-service">{e.label}</span>
                <span className="intel-risk-note">{e.risk}</span>
                <span className="intel-chevron">{isOpen ? '▾' : '▸'}</span>
              </button>

              {/* Expanded details */}
              {isOpen && (
                <div className="intel-entry__details">
                  <p className="intel-detail__risk">{e.risk}</p>

                  {e.hints.slice(0, 2).map((hint, i) => (
                    <div key={i} className="intel-detail__hint">
                      <span className="intel-detail__bullet">›</span>
                      <span>{hint}</span>
                    </div>
                  ))}

                  {e.scripts.length > 0 && (
                    <div className="intel-detail__scripts">
                      <span className="intel-detail__scripts-label">NSE:</span>
                      {e.scripts.slice(0, 3).map((s, i) => (
                        <code key={i} className="intel-script-tag">{s}</code>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
