import React, { useMemo, useState, useCallback } from 'react';
import { parseScanSummary } from '../utils/commandBuilder';
import { getPortIntel } from '../data/portIntel';

/**
 * Build a deduplicated list of follow-up scan suggestions from open ports.
 * Returns array of { label, cmd } with {target} replaced by the scanned target.
 */
function buildSuggestions(openPorts, scannedTarget) {
  const seen = new Set();
  const suggestions = [];

  for (const p of openPorts) {
    const intel = getPortIntel(p.port);
    if (!intel) continue;

    for (const fu of intel.followUp) {
      const key = fu.cmd;
      if (seen.has(key)) continue;
      seen.add(key);

      suggestions.push({
        port: p.port,
        service: intel.label,
        label: fu.label,
        cmd: fu.cmd.replace(/{target}/g, scannedTarget || '<target>'),
      });
    }
  }

  return suggestions;
}

export default function FollowUpPanel({ lines, scanStatus, scannedTarget, onLoadCommand }) {
  const { openPorts } = useMemo(() => parseScanSummary(lines), [lines]);
  const suggestions = useMemo(
    () => buildSuggestions(openPorts, scannedTarget),
    [openPorts, scannedTarget]
  );

  const [copiedIdx, setCopiedIdx] = useState(null);

  const handleCopy = useCallback((cmd, idx) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 1600);
    });
  }, []);

  if (scanStatus !== 'done' && scanStatus !== 'killed') return null;
  if (suggestions.length === 0) return null;

  return (
    <div className="followup-panel">
      <div className="followup-panel__header">
        <span className="followup-panel__title">FOLLOW-UP SCANS</span>
        <span className="followup-panel__count">{suggestions.length} suggestion{suggestions.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="followup-panel__body">
        {suggestions.map((s, i) => (
          <div key={i} className="followup-row">
            <div className="followup-row__meta">
              <span className="followup-row__service">{s.service}</span>
              <span className="followup-row__label">{s.label}</span>
            </div>
            <code className="followup-row__cmd">{s.cmd}</code>
            <div className="followup-row__actions">
              <button
                className={`btn btn--xs btn--copy ${copiedIdx === i ? 'btn--copied' : ''}`}
                onClick={() => handleCopy(s.cmd, i)}
                title="Copy this command to clipboard"
              >
                {copiedIdx === i ? '✓' : '⎘'}
              </button>
              {onLoadCommand && (
                <button
                  className="btn btn--xs btn--ghost"
                  onClick={() => onLoadCommand(s.cmd)}
                  title="Load this command into the builder"
                >
                  ↗
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
