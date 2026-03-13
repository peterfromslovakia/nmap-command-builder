import React from 'react';
import { PRESETS } from '../data/presets';

export default function PresetsTab({ onLoadPreset, advancedMode }) {
  const visiblePresets = PRESETS.filter((p) => p.safe || advancedMode);

  return (
    <div className="presets-tab">
      <p className="presets-intro">
        Click a preset to load it into the builder. You can then adjust flags before running.
      </p>

      <div className="presets-grid">
        {visiblePresets.map((preset) => (
          <button
            key={preset.id}
            className={`preset-card ${preset.requiresRoot ? 'preset-card--root' : ''} ${preset.warning ? 'preset-card--warn' : ''}`}
            onClick={() => onLoadPreset(preset)}
            title={preset.hint}
          >
            <div className="preset-card__header">
              <span className="preset-card__icon">{preset.icon}</span>
              <span className="preset-card__name">{preset.name}</span>
              <div className="preset-card__badges">
                {preset.requiresRoot && (
                  <span className="badge badge--root badge--xs">ROOT</span>
                )}
                {preset.warning && (
                  <span className="badge badge--warn badge--xs">⚠</span>
                )}
              </div>
            </div>
            <p className="preset-card__desc">{preset.description}</p>
            <code className="preset-card__hint">{preset.hint}</code>
          </button>
        ))}
      </div>
    </div>
  );
}
