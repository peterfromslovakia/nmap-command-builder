import React from 'react';

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
          <span className="badge badge--root" title="This scan type requires root / sudo">
            ⚠ ROOT
          </span>
        )}
        {isAdvanced && (
          <span className="badge badge--adv" title="Advanced flags are active">
            ⚡ ADV
          </span>
        )}
        {hasIdsRisk && (
          <span className="badge badge--ids" title="Active flags may trigger IDS / IPS detection systems">
            ⚠ IDS/IPS
          </span>
        )}
        {warnings.length > 0 && (
          <span className="badge badge--warn" title={warnings.join('\n')}>
            ⚠ {warnings.length} WARNING{warnings.length > 1 ? 'S' : ''}
          </span>
        )}
        <button
          className="btn btn--sm btn--copy"
          onClick={onCopy}
          disabled={!hasTarget && command === 'nmap'}
          title="Copy command to clipboard"
        >
          {copied ? '✓ COPIED' : '⎘ COPY'}
        </button>
        <button
          className="btn btn--sm btn--clear"
          onClick={onClear}
          title="Clear all selections"
        >
          ✕ CLEAR
        </button>
      </div>
    </div>
  );
}
