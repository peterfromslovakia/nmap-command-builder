import React, { useMemo } from 'react';
import { diffScans, baselinesFor } from '../utils/scanDiff';
import { useLang } from '../i18n/ui';
import { tr } from '../i18n/report';

const fmt = (iso) => {
  try {
    return new Date(iso).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  } catch (_) {
    return iso;
  }
};

function Section({ title, items, tone, render }) {
  const { t } = useLang();
  if (!items.length) return null;
  return (
    <div className={`diff-section diff-section--${tone}`}>
      <div className="diff-section__title">{t(title)} <span className="diff-section__count">{items.length}</span></div>
      {items.map((x, i) => <div key={i} className="diff-row">{render(x)}</div>)}
    </div>
  );
}

const PortLabel = ({ p }) => (
  <>
    <code>{p.port}/{p.proto}</code> <span className="diff-svc">{p.service}</span>
    {p.version && <span className="diff-ver">{p.version}</span>}
    <span className="diff-host">{p.host}</span>
  </>
);

/**
 * Porovnanie aktualneho skenu s predchadzajucim skenom toho isteho targetu.
 */
export default function DiffPanel({ current, snapshots, baselineId, onBaselineChange, onClearSaved }) {
  const { lang, t } = useLang();
  const portLabel = (p) => <PortLabel p={p} />;
  const baselines = useMemo(() => (current ? baselinesFor(snapshots, current) : []), [snapshots, current]);

  const baseline = baselines.find((b) => b.id === baselineId) || baselines[0];
  const diff = useMemo(() => (baseline && current ? diffScans(baseline, current) : null), [baseline, current]);

  if (!current) return null;

  return (
    <div className="diff-panel">
      <div className="intel-panel__header">
        <span className="diff-panel__title">{t('CHANGES SINCE PREVIOUS SCAN')}</span>
        {diff && (
          <div className="intel-panel__summary">
            {diff.openedPorts.length + diff.newHosts.length > 0 && (
              <span className="sev-badge sev-badge--high">+{diff.openedPorts.length + diff.newHosts.length} {t('NEW')}</span>
            )}
            {diff.newFindings.length > 0 && (
              <span className="sev-badge sev-badge--critical">+{diff.newFindings.length} {t('VULN')}</span>
            )}
            {diff.resolvedFindings.length > 0 && (
              <span className="diff-badge--ok">−{diff.resolvedFindings.length} {t('FIXED')}</span>
            )}
          </div>
        )}
      </div>

      <div className="diff-panel__body">
        {!baseline ? (
          <div className="findings-empty">
            {t('First saved scan of')} <code>{current.target}</code>. {t('The next scan of this target will be compared with it.')}
          </div>
        ) : (
          <>
            <div className="diff-baseline">
              <label>
                {t('compared with')}{' '}
                <select
                  className="flag-select"
                  value={baseline.id}
                  onChange={(e) => onBaselineChange(Number(e.target.value))}
                >
                  {baselines.map((b) => (
                    <option key={b.id} value={b.id}>{fmt(b.time)} · {b.command}</option>
                  ))}
                </select>
              </label>
              {!diff.sameCommand && (
                <span className="diff-warn">⚠ {t('different command — some differences may come from different options')}</span>
              )}
            </div>

            {diff.total === 0 && <div className="findings-empty">✓ {t('No changes since {time}.', { time: fmt(baseline.time) })}</div>}

            <Section title="NEW VULNERABILITIES" tone="bad" items={diff.newFindings}
              render={(f) => <><span className={`sev-badge sev-badge--${f.severity}`}>{t(f.severity.toUpperCase())}</span> {tr(f.title, lang)} <span className="diff-host">{f.host}{f.port ? ` · ${f.port}` : ''}</span></>} />
            <Section title="NEW OPEN PORTS" tone="bad" items={diff.openedPorts} render={portLabel} />
            <Section title="NEW HOSTS" tone="bad" items={diff.newHosts}
              render={(h) => <><code>{h.host}</code> <span className="diff-ver">{h.ports.map((p) => p.port).join(', ') || t('no open ports')}</span></>} />
            <Section title="VERSION CHANGES" tone="info" items={diff.changedVersions}
              render={(c) => <><code>{c.port}/{c.proto}</code> <span className="diff-svc">{c.service}</span> <span className="diff-ver">{c.from} → {c.to}</span> <span className="diff-host">{c.host}</span></>} />
            <Section title="FIXED VULNERABILITIES" tone="good" items={diff.resolvedFindings}
              render={(f) => <>{tr(f.title, lang)} <span className="diff-host">{f.host}{f.port ? ` · ${f.port}` : ''}</span></>} />
            <Section title="CLOSED PORTS" tone="good" items={diff.closedPorts} render={portLabel} />
            <Section title="FILTERED PORTS" tone="info" items={diff.filteredPorts || []} render={portLabel} />
            <Section title="NOT TESTED PORTS" tone="info" items={diff.notTestedPorts || []} render={portLabel} />
            <Section title="HOSTS NOT FOUND" tone="info" items={diff.goneHosts}
              render={(h) => <><code>{h.host}</code> <span className="diff-ver">{t('down or filtered')}</span></>} />
          </>
        )}
        <button className="link-btn diff-forget" onClick={onClearSaved} title={t('Delete all saved scan results from this computer')}>
          {t('forget saved scans ({n})', { n: snapshots.length })}
        </button>
      </div>
    </div>
  );
}
