import React, { useState } from 'react';
import { MONITOR_INTERVALS } from '../utils/monitor';
import { useT } from '../i18n/ui';

const intervalLabel = (min, t) => (min < 60 ? t('{n} min', { n: min }) : min < 1440 ? t('{n} h', { n: min / 60 }) : t('24 h'));
const time = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

function resultText(m, t) {
  const c = m.lastCounts;
  switch (m.lastResult) {
    case 'first': return t('first run saved — changes are reported from the next one');
    case 'nochange': return t('no new ports, devices or vulnerabilities');
    case 'nohosts': return t('no device responded');
    case 'error': return t('scan failed');
    case 'changes': return [
      c.findings && t('{n} new vulnerabilities', { n: c.findings }),
      c.ports && t('{n} new open ports', { n: c.ports }),
      c.hosts && t('{n} new devices', { n: c.hosts }),
    ].filter(Boolean).join(', ');
    default: return '';
  }
}

/**
 * Monitorovanie: zopakuje posledny sken v intervale a upozorni na nove porty,
 * zariadenia a zranitelnosti. Bezi len ked je aplikacia otvorena.
 */
export default function MonitorBar({ monitor, canStart, lastTarget, scanning, onStart, onStop, onRunNow, reportDir = '', onChooseReportDir }) {
  const t = useT();
  const [interval, setIntervalMin] = useState(60);

  if (!monitor) {
    if (!canStart) return null;
    return (
      <div className="monitor-bar">
        <span className="monitor-bar__icon">⟳</span>
        <span className="monitor-bar__text">
          {t('Repeat this scan of {target} every', { target: lastTarget })}
        </span>
        <select className="flag-select monitor-bar__select" value={interval} onChange={(e) => setIntervalMin(Number(e.target.value))} aria-label={t('Repeat interval')}>
          {MONITOR_INTERVALS.map((m) => <option key={m} value={m}>{intervalLabel(m, t)}</option>)}
        </select>
        <span className="monitor-bar__text monitor-bar__dim">{t('and notify me about new ports, devices or vulnerabilities')}</span>
        <button className="btn btn--xs monitor-bar__start" onClick={() => onStart(interval)}>{t('START MONITORING')}</button>
      </div>
    );
  }

  const result = resultText(monitor, t);
  return (
    <div className={`monitor-bar monitor-bar--active ${monitor.lastResult === 'changes' ? 'monitor-bar--alert' : ''}`}>
      <span className="monitor-bar__icon monitor-bar__icon--spin">⟳</span>
      <span className="monitor-bar__label">{t('MONITORING')}</span>
      <code className="monitor-bar__target" title={monitor.command}>{monitor.target}</code>
      <span className="monitor-bar__text">
        {t('every {interval}', { interval: intervalLabel(monitor.intervalMin, t) })}
        {' · '}{scanning ? t('scan running…') : t('next at {time}', { time: time(monitor.nextRun) })}
        {monitor.runs > 0 && <> · {t('runs: {n}', { n: monitor.runs })}</>}
      </span>
      {result && <span className="monitor-bar__result">{monitor.lastResult === 'changes' || monitor.lastResult === 'error' ? '⚠ ' : '✓ '}{result}</span>}
      <span className="monitor-bar__actions">
        <button className="btn btn--xs" onClick={onRunNow} disabled={scanning}>{t('RUN NOW')}</button>
        <button className="btn btn--xs btn--ghost" onClick={onStop}>{t('STOP')}</button>
      </span>
      <span className="monitor-bar__hint">
        {t('Runs only while the app is open.')}
        {onChooseReportDir && (
          <span className="monitor-bar__reports">
            {reportDir ? (
              <>
                {t('PDF report on changes →')} <code title={reportDir}>{reportDir.split(/[\\/]/).filter(Boolean).pop()}</code>
                {' '}<button className="link-btn" onClick={() => onChooseReportDir()}>{t('change')}</button>
                {' '}<button className="link-btn" onClick={() => onChooseReportDir(true)}>{t('turn off')}</button>
              </>
            ) : (
              <button className="link-btn" title={t('Save a PDF report automatically after the first run and whenever something changes')} onClick={() => onChooseReportDir()}>
                {t('save PDF reports automatically…')}
              </button>
            )}
          </span>
        )}
      </span>
    </div>
  );
}
