import React from 'react';

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}

function statusIcon(entry) {
  if (entry.status === 'success') return '✓';
  if (entry.status === 'killed') return '⊗';
  if (entry.status === 'error') return '✗';
  return '?';
}

function statusClass(entry) {
  if (entry.status === 'success') return 'hist-status--ok';
  if (entry.status === 'killed') return 'hist-status--killed';
  return 'hist-status--error';
}

export default function ScanHistory({ history, onLoad }) {
  if (history.length === 0) return null;

  return (
    <div className="scan-history">
      <div className="scan-history__title">SCAN HISTORY</div>
      <div className="scan-history__list">
        {history.map((entry, i) => (
          <div key={i} className="hist-entry">
            <span className={`hist-status ${statusClass(entry)}`}>
              {statusIcon(entry)}
            </span>
            <span className="hist-time">{formatTime(entry.time)}</span>
            <button
              className="hist-cmd"
              onClick={() => onLoad(entry)}
              title={`Reload: ${entry.command}`}
            >
              {entry.command}
            </button>
            {entry.exitCode !== null && entry.exitCode !== undefined && (
              <span className={`hist-code ${entry.exitCode === 0 ? 'hist-code--ok' : 'hist-code--err'}`}>
                exit:{entry.exitCode}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
