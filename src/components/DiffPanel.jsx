import React, { useEffect, useMemo, useState } from 'react';
import { diffScans, baselinesFor } from '../utils/scanDiff';

const fmt = (iso) => {
  try {
    return new Date(iso).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  } catch (_) {
    return iso;
  }
};

function Section({ title, items, tone, render }) {
  if (!items.length) return null;
  return (
    <div className={`diff-section diff-section--${tone}`}>
      <div className="diff-section__title">{title} <span className="diff-section__count">{items.length}</span></div>
      {items.map((x, i) => <div key={i} className="diff-row">{render(x)}</div>)}
    </div>
  );
}

const portLabel = (p) => (
  <>
    <code>{p.port}/{p.proto}</code> <span className="diff-svc">{p.service}</span>
    {p.version && <span className="diff-ver">{p.version}</span>}
    <span className="diff-host">{p.host}</span>
  </>
);

/**
 * Porovnanie aktualneho skenu s predchadzajucim skenom toho isteho targetu.
 */
export default function DiffPanel({ current, snapshots, onClearSaved }) {
  const baselines = useMemo(() => (current ? baselinesFor(snapshots, current) : []), [snapshots, current]);
  const [baselineId, setBaselineId] = useState(null);
  useEffect(() => { setBaselineId(baselines[0]?.id ?? null); }, [current?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const baseline = baselines.find((b) => b.id === baselineId) || baselines[0];
  const diff = useMemo(() => (baseline && current ? diffScans(baseline, current) : null), [baseline, current]);

  if (!current) return null;

  return (
    <div className="diff-panel">
      <div className="intel-panel__header">
        <span className="diff-panel__title">CHANGES SINCE PREVIOUS SCAN</span>
        {diff && (
          <div className="intel-panel__summary">
            {diff.openedPorts.length + diff.newHosts.length > 0 && (
              <span className="sev-badge sev-badge--high">+{diff.openedPorts.length + diff.newHosts.length} NEW</span>
            )}
            {diff.newFindings.length > 0 && (
              <span className="sev-badge sev-badge--critical">+{diff.newFindings.length} VULN</span>
            )}
            {diff.resolvedFindings.length > 0 && (
              <span className="diff-badge--ok">−{diff.resolvedFindings.length} FIXED</span>
            )}
          </div>
        )}
      </div>

      <div className="diff-panel__body">
        {!baseline ? (
          <div className="findings-empty">
            First saved scan of <code>{current.target}</code>. The next scan of this target will be compared with it.
          </div>
        ) : (
          <>
            <div className="diff-baseline">
              <label>
                compared with{' '}
                <select
                  className="flag-select"
                  value={baseline.id}
                  onChange={(e) => setBaselineId(Number(e.target.value))}
                >
                  {baselines.map((b) => (
                    <option key={b.id} value={b.id}>{fmt(b.time)} · {b.command}</option>
                  ))}
                </select>
              </label>
              {!diff.sameCommand && (
                <span className="diff-warn">⚠ different command — some differences may come from different options</span>
              )}
            </div>

            {diff.total === 0 && <div className="findings-empty">✓ No changes since {fmt(baseline.time)}.</div>}

            <Section title="NEW VULNERABILITIES" tone="bad" items={diff.newFindings}
              render={(f) => <><span className={`sev-badge sev-badge--${f.severity}`}>{f.severity.toUpperCase()}</span> {f.title} <span className="diff-host">{f.host}{f.port ? ` · ${f.port}` : ''}</span></>} />
            <Section title="NEW OPEN PORTS" tone="bad" items={diff.openedPorts} render={portLabel} />
            <Section title="NEW HOSTS" tone="bad" items={diff.newHosts}
              render={(h) => <><code>{h.host}</code> <span className="diff-ver">{h.ports.map((p) => p.port).join(', ') || 'no open ports'}</span></>} />
            <Section title="VERSION CHANGES" tone="info" items={diff.changedVersions}
              render={(c) => <><code>{c.port}/{c.proto}</code> <span className="diff-svc">{c.service}</span> <span className="diff-ver">{c.from} → {c.to}</span> <span className="diff-host">{c.host}</span></>} />
            <Section title="FIXED VULNERABILITIES" tone="good" items={diff.resolvedFindings}
              render={(f) => <>{f.title} <span className="diff-host">{f.host}{f.port ? ` · ${f.port}` : ''}</span></>} />
            <Section title="CLOSED PORTS" tone="good" items={diff.closedPorts} render={portLabel} />
            <Section title="HOSTS NOT FOUND" tone="info" items={diff.goneHosts}
              render={(h) => <><code>{h.host}</code> <span className="diff-ver">down or filtered</span></>} />
          </>
        )}
        <button className="link-btn diff-forget" onClick={onClearSaved} title="Delete all saved scan results from this computer">
          forget saved scans ({snapshots.length})
        </button>
      </div>
    </div>
  );
}
