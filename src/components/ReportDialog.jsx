import React, { useEffect, useRef, useState } from 'react';
import { REPORT_LANGS } from '../i18n/report';
import { useT } from '../i18n/ui';

const FIELDS = [
  ['tester', 'Performed by', 'Name of the person who ran the test'],
  ['organization', 'Organisation', 'Company / team (optional)'],
  ['client', 'Client / system owner', 'Whose systems were tested (optional)'],
  ['authorization', 'Authorisation ref.', 'Contract / order / ticket number (optional)'],
];

/**
 * Udaje do reportu pred exportom: jazyk, kto test vykonal, pre koho a na zaklade coho.
 */
export default function ReportDialog({ format, initial, onCancel, onGenerate }) {
  const t = useT();
  const [meta, setMeta] = useState(initial);
  const first = useRef(null);
  useEffect(() => { first.current?.focus(); }, []);
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onCancel]);

  const set = (k) => (e) => setMeta((m) => ({ ...m, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }));

  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <form
        className="modal report-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-dialog-title"
        onSubmit={(e) => { e.preventDefault(); onGenerate(meta); }}
      >
        <div className="modal__title" id="report-dialog-title">{t('REPORT')} — {format.toUpperCase()}</div>

        <div className="report-dialog__langs" role="radiogroup" aria-label={t('Report language')}>
          <span className="report-dialog__label">{t('Language')}</span>
          {Object.entries(REPORT_LANGS).map(([code, name]) => (
            <label key={code} className={`lang-option ${meta.lang === code ? 'lang-option--active' : ''}`}>
              <input type="radio" name="lang" value={code} checked={meta.lang === code} onChange={set('lang')} />
              {code.toUpperCase()} · {name}
            </label>
          ))}
        </div>

        {FIELDS.map(([key, label, hint], i) => (
          <label key={key} className="report-dialog__field">
            <span className="report-dialog__label">{t(label)}</span>
            <input
              ref={i === 0 ? first : undefined}
              className="flag-input"
              value={meta[key]}
              maxLength={120}
              placeholder={t(hint)}
              onChange={set(key)}
              spellCheck={false}
            />
          </label>
        ))}

        <label className="report-dialog__remember">
          <input type="checkbox" checked={meta.remember} onChange={set('remember')} />
          {' '}{t('Remember these details on this computer')}
        </label>

        <div className="modal__actions">
          <button type="button" className="btn btn--sm" onClick={onCancel}>{t('CANCEL')}</button>
          <button type="submit" className="btn btn--sm btn--primary">↓ {t('GENERATE')} {format.toUpperCase()}</button>
        </div>
      </form>
    </div>
  );
}
