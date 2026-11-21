import React from 'react';
import { useT } from '../i18n/ui';

export default function CommandPreview({
  command,
  warnings,
  requiresRoot,
  hasTarget,
  isAdvanced,
  hasIdsRisk,
  copied,
  onCopy,
  onClear,
}) {
  const t = useT();
  return (
    <div className="cmd-preview-bar">
      <div className="cmd-preview-prompt">
        <span className="cmd-prompt-char">$</span>
        <span className={`cmd-text ${!hasTarget ? 'cmd-text--dim' : ''}`}>
          {command}
          <span className="cmd-cursor" />
        </span>
      </div>

      <div className="cmd-actions">
        {requiresRoot && (
          <span className="badge badge--root" title={t('This scan type requires root / sudo')}>
            ⚠ ROOT
          </span>
        )}
        {isAdvanced && (
          <span className="badge badge--adv" title={t('Advanced flags are active')}>
            ⚡ ADV
          </span>
        )}
        {hasIdsRisk && (
          <span className="badge badge--ids" title={t('Active flags may trigger IDS / IPS detection systems')}>
            ⚠ IDS/IPS
          </span>
        )}
        {warnings.length > 0 && (
          <span className="badge badge--warn" title={warnings.map((w) => t(w)).join('\n')}>
            ⚠ {warnings.length} {warnings.length > 1 ? t('WARNINGS') : t('WARNING')}
          </span>
        )}
        <button
          className="btn btn--sm btn--copy"
          onClick={onCopy}
          disabled={!hasTarget && command === 'nmap'}
          title={t('Copy command to clipboard')}
        >
          {copied ? `✓ ${t('COPIED')}` : `⎘ ${t('COPY')}`}
        </button>
        <button
          className="btn btn--sm btn--clear"
          onClick={onClear}
          title={t('Clear all selections')}
        >
          ✕ {t('CLEAR')}
        </button>
      </div>
    </div>
  );
}
