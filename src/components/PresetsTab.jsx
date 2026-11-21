import React, { useState } from 'react';
import { buildCommand } from '../utils/commandBuilder';
import { PRESETS } from '../data/presets';
import { useT } from '../i18n/ui';

const RISK = {
  low:    { label: 'LOW',       title: 'Standard scan' },
  medium: { label: 'NOISY',     title: 'Likely to be logged / detected by IDS' },
  high:   { label: 'INTRUSIVE', title: 'May disrupt services or lock accounts — written permission required' },
};

function MyPresets({ userPresets, canSave, currentTarget, onSave, onDelete, onLoad, onExport, onImport }) {
  const t = useT();
  const [name, setName] = useState('');
  const [withTarget, setWithTarget] = useState(false);
  const [msg, setMsg] = useState(null);
  const [confirmId, setConfirmId] = useState(null);

  const save = (e) => {
    e.preventDefault();
    const r = onSave(name, withTarget);
    if (r.ok) { setMsg({ ok: true, text: t('Saved "{name}"', { name: name.trim() }) }); setName(''); }
    else setMsg({ ok: false, text: /^Limit is (\d+) presets$/.test(r.error) ? t('Limit is {n} presets', { n: r.error.match(/\d+/)[0] }) : t(r.error) });
  };

  return (
    <section className="my-presets">
      <div className="my-presets__head">
        <span className="my-presets__title">{t('MY PRESETS')}</span>
        <span className="my-presets__io">
          {onImport && (
            <button className="link-btn" title={t('Load presets from a file (e.g. from a colleague)')} onClick={async () => {
              const r = await onImport();
              if (!r) return;
              if (!r.ok) setMsg({ ok: false, text: t(r.error) });
              else setMsg({ ok: true, text: t('Imported: {added} new, {replaced} replaced, {skipped} skipped', r) });
            }}>↑ {t('import')}</button>
          )}
          {onExport && userPresets.length > 0 && (
            <button className="link-btn" title={t('Save all my presets to a file to share or back up')} onClick={onExport}>↓ {t('export')}</button>
          )}
        </span>
      </div>
      <form className="my-presets__form" onSubmit={save}>
        <input
          className="flag-input my-presets__name"
          value={name}
          maxLength={60}
          onChange={(e) => { setName(e.target.value); setMsg(null); }}
          placeholder={canSave ? t('Name for the current flags, e.g. Weekly NAS check') : t('Select flags in BUILDER first')}
          disabled={!canSave}
          spellCheck={false}
        />
        <label className="my-presets__target" title={t('Also remember the current target')}>
          <input type="checkbox" checked={withTarget} onChange={(e) => setWithTarget(e.target.checked)} disabled={!canSave} />
          {' '}+ {t('target')}{currentTarget ? <code> {currentTarget}</code> : ''}
        </label>
        <button className="btn btn--sm" type="submit" disabled={!canSave || !name.trim()}>{t('SAVE')}</button>
      </form>
      {msg && <div className={`my-presets__msg my-presets__msg--${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div>}

      {userPresets.length === 0 ? (
        <p className="my-presets__empty">
          {t('Build a scan in BUILDER, then save it here to reuse it with one click. Saved only on this computer.')}
        </p>
      ) : (
        <div className="my-presets__list">
          {userPresets.map((p) => (
            <div key={p.id} className="my-preset">
              <button className="my-preset__load" onClick={() => onLoad(p)} title={t('Load into the builder')}>
                <span className="my-preset__name">{p.name}</span>
                {p.requiresRoot && <span className="badge badge--root badge--xs">ROOT</span>}
                <code className="my-preset__cmd">{buildCommand(p.target || '<target>', p.flags, true).command}</code>
              </button>
              {confirmId === p.id ? (
                <span className="my-preset__confirm">
                  <button className="link-btn my-preset__del" onClick={() => { onDelete(p.id); setConfirmId(null); }}>{t('delete')}</button>
                  {' / '}
                  <button className="link-btn" onClick={() => setConfirmId(null)}>{t('keep')}</button>
                </span>
              ) : (
                <button className="link-btn my-preset__del" onClick={() => setConfirmId(p.id)} title={t('Delete this preset')}>✕</button>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default function PresetsTab({
  onLoadPreset, advancedMode, userPresets = [], canSave = false, currentTarget = '', onSaveUserPreset, onDeleteUserPreset, onExportPresets, onImportPresets,
}) {
  const t = useT();
  const visiblePresets = PRESETS.filter((p) => p.safe || advancedMode);

  return (
    <div className="presets-tab">
      <p className="presets-intro">
        {t('Click a preset to load it into the builder. You can then adjust flags before running.')}
      </p>

      <MyPresets
        userPresets={userPresets}
        canSave={canSave}
        currentTarget={currentTarget}
        onSave={onSaveUserPreset}
        onDelete={onDeleteUserPreset}
        onExport={onExportPresets}
        onImport={onImportPresets}
        onLoad={onLoadPreset}
      />

      <div className="my-presets__title">{t('BUILT-IN')}</div>
      <div className="presets-legend">
        {Object.entries(RISK).map(([k, r]) => (
          <span key={k} className="presets-legend__item">
            <span className={`risk-badge risk-badge--${k}`}>{t(r.label)}</span> {t(r.title)}
          </span>
        ))}
        {!advancedMode && (
          <span className="presets-legend__item presets-legend__hint">
            {t('Switch to ADV to see {n} more dangerous presets.', { n: PRESETS.length - visiblePresets.length })}
          </span>
        )}
      </div>

      <div className="presets-grid">
        {visiblePresets.map((preset) => (
          <button
            key={preset.id}
            className={`preset-card preset-card--risk-${preset.risk || 'low'}`}
            onClick={() => onLoadPreset(preset)}
            title={preset.hint}
          >
            <div className="preset-card__header">
              <span className="preset-card__icon">{preset.icon}</span>
              <span className="preset-card__name">{t(preset.name)}</span>
              <div className="preset-card__badges">
                <span
                  className={`risk-badge risk-badge--${preset.risk || 'low'}`}
                  title={t(RISK[preset.risk || 'low'].title)}
                >
                  {t(RISK[preset.risk || 'low'].label)}
                </span>
                {preset.requiresRoot && (
                  <span className="badge badge--root badge--xs">ROOT</span>
                )}
              </div>
            </div>
            <p className="preset-card__desc">{t(preset.description)}</p>
            {(preset.riskNote || preset.warning) && (
              <p className={`preset-card__risk preset-card__risk--${preset.risk || 'low'}`}>
                ⚠ {t(preset.riskNote || preset.warning)}
              </p>
            )}
            <code className="preset-card__hint">{preset.hint}</code>
          </button>
        ))}
      </div>
    </div>
  );
}
