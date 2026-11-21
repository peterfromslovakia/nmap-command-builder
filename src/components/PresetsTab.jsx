import React from 'react';
import { PRESETS } from '../data/presets';

const RISK = {
  low:    { label: 'LOW',       title: 'Standard scan' },
  medium: { label: 'NOISY',     title: 'Likely to be logged / detected by IDS' },
  high:   { label: 'INTRUSIVE', title: 'May disrupt services or lock accounts — written permission required' },
};

export default function PresetsTab({ onLoadPreset, advancedMode }) {
  const visiblePresets = PRESETS.filter((p) => p.safe || advancedMode);

  return (
    <div className="presets-tab">
      <p className="presets-intro">
        Click a preset to load it into the builder. You can then adjust flags before running.
      </p>
      <div className="presets-legend">
        {Object.entries(RISK).map(([k, r]) => (
          <span key={k} className="presets-legend__item">
            <span className={`risk-badge risk-badge--${k}`}>{r.label}</span> {r.title}
          </span>
        ))}
        {!advancedMode && (
          <span className="presets-legend__item presets-legend__hint">
            Switch to ADV to see {PRESETS.length - visiblePresets.length} more dangerous presets.
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
              <span className="preset-card__name">{preset.name}</span>
              <div className="preset-card__badges">
                <span
                  className={`risk-badge risk-badge--${preset.risk || 'low'}`}
                  title={RISK[preset.risk || 'low'].title}
                >
                  {RISK[preset.risk || 'low'].label}
                </span>
                {preset.requiresRoot && (
                  <span className="badge badge--root badge--xs">ROOT</span>
                )}
              </div>
            </div>
            <p className="preset-card__desc">{preset.description}</p>
            {(preset.riskNote || preset.warning) && (
              <p className={`preset-card__risk preset-card__risk--${preset.risk || 'low'}`}>
                ⚠ {preset.riskNote || preset.warning}
              </p>
            )}
            <code className="preset-card__hint">{preset.hint}</code>
          </button>
        ))}
      </div>
    </div>
  );
}
