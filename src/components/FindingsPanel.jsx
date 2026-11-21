import React, { useMemo, useState } from 'react';
import { parseFindings } from '../utils/findings';
import { formatEpss } from '../utils/intel';

const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW' };

/**
 * Zranitelnosti a nebezpecne konfiguracie najdene NSE skriptami + ako ich opravit.
 * Ak sken nespustal skripty, ponukne tip ako ich spustit.
 */
function IntelStatus({ intel, onToggle }) {
  if (!intel) return null;
  const { enabled, loading, meta, nvdDone, nvdTotal } = intel;
  return (
    <div className="intel-status">
      {!enabled ? (
        <span>Online vulnerability data is off.</span>
      ) : loading ? (
        <span><span className="btn-spinner" /> Checking CISA KEV and EPSS…</span>
      ) : meta ? (
        <span>
          Checked against <b>CISA KEV</b>{meta.kevVersion ? ` ${meta.kevVersion}` : ''}{meta.kevStale ? ' (offline copy)' : ''} · <b>EPSS</b>
          {nvdTotal > 0 && <> · <b>NVD</b> {nvdDone < nvdTotal ? `${nvdDone}/${nvdTotal}…` : 'details loaded'}</>}
          {meta.errors.length > 0 && <span className="intel-status__err" title={meta.errors.join('\n')}> · ⚠ {meta.errors.length} source(s) unavailable</span>}
        </span>
      ) : null}
      <button className="link-btn intel-status__toggle" onClick={onToggle}
        title="Only CVE numbers are sent to FIRST.org (EPSS) and NIST (NVD); the CISA list is downloaded. No IP addresses or scan data leave this computer.">
        {enabled ? 'turn off' : 'turn on'}
      </button>
    </div>
  );
}

function CveTable({ cves }) {
  if (!cves || cves.length === 0) return null;
  return (
    <table className="cve-table">
      <thead><tr><th>CVE</th><th className="num">CVSS</th><th className="num" title="Probability of exploitation in the next 30 days (FIRST EPSS)">EPSS</th><th>STATUS</th></tr></thead>
      <tbody>
        {cves.slice(0, 12).map((c) => (
          <tr key={c.id} className={c.kev ? 'cve-row--kev' : ''}>
            <td><code>{c.id}</code>{c.nvd?.cwe?.length ? <span className="cve-cwe">{c.nvd.cwe.join(', ')}</span> : null}</td>
            <td className="num">{c.score ?? '—'}</td>
            <td className="num">{formatEpss(c.epss) || '—'}</td>
            <td>
              {c.kev ? <span className="kev-badge" title={c.kev.requiredAction}>EXPLOITED{c.kev.ransomware ? ' · RANSOMWARE' : ''}</span> : <span className="inv-dim">—</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function FindingsPanel({ lines, scanStatus, onLoadVulnScan, onExport, findings: enriched, intel, onToggleIntel }) {
  const text = useMemo(() => lines.map((l) => l.text || '').join(''), [lines]);
  const parsed = useMemo(() => parseFindings(text), [text]);
  const findings = enriched || parsed;
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
          {onExport && (
            <>
              <button className="findings-export" onClick={() => onExport('pdf')} title="Save report as PDF">
                ↓ PDF
              </button>
              <button className="findings-export" onClick={() => onExport('md')} title="Save report as Markdown">
                ↓ MD
              </button>
            </>
          )}
        </div>
      </div>

      <IntelStatus intel={intel} onToggle={onToggleIntel} />

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
                <span className="finding__title">
                  {f.title}
                  {f.exploited && <span className="kev-badge" title="Listed in the CISA Known Exploited Vulnerabilities catalogue">ACTIVELY EXPLOITED</span>}
                  {f.epssMax != null && f.epssMax >= 0.1 && <span className="epss-badge" title="Highest EPSS — probability of exploitation in the next 30 days">EPSS {formatEpss(f.epssMax)}</span>}
                </span>
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
                  {f.exploited && (
                    <div className="finding__kev">
                      ⚠ Attackers are exploiting this vulnerability right now (CISA KEV{f.ransomware ? ', used by ransomware' : ''}).
                      {' '}Fix it first{f.kevDue ? ` — US federal agencies had to fix it by ${f.kevDue}` : ''}.
                      {f.escalated && ' Severity raised to HIGH.'}
                    </div>
                  )}
                  <CveTable cves={f.cveDetails} />
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
