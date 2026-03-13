import React, { useEffect, useRef, useState } from 'react';
import { parseScanSummary } from '../utils/commandBuilder';

// ─── Line classifier ──────────────────────────────────────────────────────────
function classifyLine(line) {
  if (line.type === 'stderr' || line.type === 'error') return 'term-line--error';
  if (line.type === 'system') return 'term-line--system';
  const t = line.text;
  if (/Nmap scan report for/i.test(t)) return 'term-line--host';
  if (/Starting Nmap/i.test(t)) return 'term-line--header';
  if (/Nmap done/i.test(t)) return 'term-line--done';
  if (/\d+\/(tcp|udp)\s+open/i.test(t)) return 'term-line--open';
  if (/\d+\/(tcp|udp)\s+filtered/i.test(t)) return 'term-line--filtered';
  if (/\d+\/(tcp|udp)\s+closed/i.test(t)) return 'term-line--closed';
  if (/Host is up/i.test(t)) return 'term-line--host-up';
  if (/WARNING|CAUTION|Error/i.test(t)) return 'term-line--warn';
  return 'term-line--normal';
}

export default function TerminalOutput({ lines, scanStatus, onExport, onClear }) {
  const bodyRef = useRef(null);
  const exportRef = useRef(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const summary = scanStatus === 'done' || scanStatus === 'killed' ? parseScanSummary(lines) : null;
  const isScanning = scanStatus === 'scanning';
  const hasOutput = lines.length > 0;

  // Auto-scroll to bottom on new output
  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [lines]);

  // Close export dropdown on outside click
  useEffect(() => {
    if (!exportOpen) return;
    const handler = (e) => {
      if (exportRef.current && !exportRef.current.contains(e.target)) {
        setExportOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [exportOpen]);

  const handleCopy = () => {
    const text = lines.map((l) => l.text || '').join('');
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="terminal">
      <div className="terminal__titlebar">
        <span className="terminal__title">
          TERMINAL OUTPUT
          {isScanning && <span className="term-spinner" />}
        </span>
        <div className="terminal__actions">
          {hasOutput && (
            <>
              <button
                className={`btn btn--xs btn--ghost${copied ? ' btn--copied' : ''}`}
                onClick={handleCopy}
                title="Copy all output to clipboard"
              >
                {copied ? '✓ COPIED' : '⊞ COPY'}
              </button>

              {/* Export dropdown */}
              <div className="export-dropdown" ref={exportRef}>
                <button
                  className="btn btn--xs btn--ghost"
                  onClick={() => setExportOpen((v) => !v)}
                  title="Export output"
                >
                  ↓ EXPORT ▾
                </button>
                {exportOpen && (
                  <div className="export-menu">
                    <button
                      className="export-menu__item"
                      onClick={() => { onExport('txt'); setExportOpen(false); }}
                    >
                      <span className="export-menu__fmt">TXT</span>
                      <span className="export-menu__desc">raw terminal output</span>
                    </button>
                    <button
                      className="export-menu__item"
                      onClick={() => { onExport('json'); setExportOpen(false); }}
                    >
                      <span className="export-menu__fmt">JSON</span>
                      <span className="export-menu__desc">structured scan data</span>
                    </button>
                    <button
                      className="export-menu__item"
                      onClick={() => { onExport('csv'); setExportOpen(false); }}
                    >
                      <span className="export-menu__fmt">CSV</span>
                      <span className="export-menu__desc">open ports table</span>
                    </button>
                  </div>
                )}
              </div>

              <button
                className="btn btn--xs btn--ghost"
                onClick={onClear}
                title="Clear terminal"
              >
                ✕ CLEAR
              </button>
            </>
          )}
        </div>
      </div>

      <div className="terminal__body" ref={bodyRef}>
        {!hasOutput && (
          <div className="terminal__placeholder">
            <span className="terminal__placeholder-prompt">$</span>
            <span className="terminal__placeholder-text">
              {scanStatus === 'idle'
                ? ' Waiting for scan… Build a command and press RUN SCAN.'
                : ' Running scan…'}
            </span>
            <span className="cmd-cursor" />
          </div>
        )}

        {lines.map((line) => {
          const sublines = (line.text || '').split('\n');
          return sublines.map((sub, i) => (
            <div
              key={`${line.id}-${i}`}
              className={`term-line ${classifyLine({ ...line, text: sub })}`}
            >
              {sub || '\u00A0'}
            </div>
          ));
        })}

        {isScanning && (
          <div className="term-line term-line--system">
            <span className="term-scan-indicator">▌</span>
          </div>
        )}
      </div>

      {/* Scan summary after completion */}
      {summary && summary.openPorts.length > 0 && (
        <div className="terminal__summary">
          <span className="summary-label">SUMMARY:</span>
          <span className="summary-item">
            <span className="summary-val">{summary.hosts}</span> host{summary.hosts !== 1 ? 's' : ''}
          </span>
          <span className="summary-sep">·</span>
          <span className="summary-item">
            <span className="summary-val">{summary.openPorts.length}</span> open port{summary.openPorts.length !== 1 ? 's' : ''}
          </span>
          {summary.services.length > 0 && (
            <>
              <span className="summary-sep">·</span>
              <span className="summary-item summary-services">
                {summary.services.slice(0, 8).join(', ')}
                {summary.services.length > 8 && ` +${summary.services.length - 8} more`}
              </span>
            </>
          )}
        </div>
      )}
    </div>
  );
}
