import React, { useMemo, useState } from 'react';
import { parseFindings } from '../utils/findings';

const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW' };

/**
 * Zranitelnosti a nebezpecne konfiguracie najdene NSE skriptami + ako ich opravit.
 * Ak sken nespustal skripty, ponukne tip ako ich spustit.
 */
export default function FindingsPanel({ lines, scanStatus, onLoadVulnScan }) {
  const text = useMemo(() => lines.map((l) => l.text || '').join(''), [lines]);
  const findings = useMemo(() => parseFindings(text), [text]);
  const ranScripts = useMemo(() => /^\|[_ ]/m.test(text), [text]);
  const hasOpenPorts = useMemo(() => /^\d+\/(tcp|udp)\s+open\b/m.test(text), [text]);

  // Kriticke a vysoke nalezy su rozbalene automaticky.
  const [toggled, setToggled] = useState(new Set());
  const isOpen = (f, i) => {
    const key = `${f.id}|${f.host}|${f.port}|${i}`;
    const auto = f.severity === 'critical' || f.severity === 'high';
    return toggled.has(key) ? !auto : auto;
  };
  const toggle = (f, i) => {
    const key = `${f.id}|${f.host}|${f.port}|${i}`;
    setToggled((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  if (scanStatus !== 'done' && scanStatus !== 'killed') return null;
  if (!hasOpenPorts && findings.length === 0) return null;

  const counts = findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {});
  const copy = (url) => { if (navigator.clipboard) navigator.clipboard.writeText(url); };

  return (
    <div className="findings-panel">
      <div className="intel-panel__header">
        <span className="findings-panel__title">VULNERABILITIES &amp; FIXES</span>
        <div className="intel-panel__summary">
          {['critical', 'high', 'medium', 'low'].map((s) =>
            counts[s] ? (
              <span key={s} className={`sev-badge sev-badge--${s}`}>
                {counts[s]} {SEV_LABEL[s]}
              </span>
            ) : null
          )}
        </div>
      </div>

      <div className="findings-panel__body">
        {findings.length === 0 && (
          <div className="findings-empty">
            {ranScripts
              ? '✓ No known vulnerabilities detected by the scripts that ran.'
              : 'No vulnerability scripts were run in this scan.'}
            {onLoadVulnScan && (
              <button className="link-btn" onClick={onLoadVulnScan}>
                Add -sV --script vuln,vulners to the builder
              </button>
            )}
          </div>
        )}

        {findings.map((f, i) => {
          const open = isOpen(f, i);
          return (
            <div key={`${f.id}-${f.host}-${f.port}-${i}`} className={`finding finding--${f.severity}`}>
              <button className="finding__row" onClick={() => toggle(f, i)}>
                <span className={`sev-badge sev-badge--${f.severity}`}>{SEV_LABEL[f.severity]}</span>
                <span className="finding__title">{f.title}</span>
                <span className="finding__where">
                  {f.host}{f.port ? ` · ${f.port}` : ''}
                </span>
                <span className="intel-chevron">{open ? '▾' : '▸'}</span>
              </button>

              {open && (
                <div className="finding__details">
                  {f.evidence && (
                    <div className="finding__evidence">
                      <span className="finding__label">FOUND</span>
                      <code>{f.evidence}</code>
                      <span className="finding__script">({f.script})</span>
                    </div>
                  )}
                  <div className="finding__label finding__label--fix">HOW TO FIX</div>
                  <ol className="finding__fix">
                    {f.fix.map((step, j) => <li key={j}>{step}</li>)}
                  </ol>
                  {f.refs && f.refs.length > 0 && (
                    <div className="finding__refs">
                      {f.refs.map((r) => (
                        <button key={r} className="finding__ref" onClick={() => copy(r)} title="Click to copy link">
                          {r}
                        </button>
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
