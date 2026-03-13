import React from 'react';

export default function FlagCategory({
  category,
  flagSelections,
  onFlagChange,
  advancedMode,
  searchQuery,
  expanded,
  onToggle,
}) {
  // Filter flags by search query
  const visibleFlags = category.flags.filter((f) => {
    if (!f.safe && !advancedMode) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.name.toLowerCase().includes(q) ||
      f.flag.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q)
    );
  });

  if (visibleFlags.length === 0) return null;

  return (
    <div className={`flag-category ${!category.safe ? 'flag-category--advanced' : ''}`}>
      <button className="flag-category__header" onClick={onToggle}>
        <span className="flag-category__icon">{category.icon}</span>
        <span className="flag-category__name">{category.name}</span>
        {!category.safe && (
          <span className="badge badge--adv badge--xs">ADV</span>
        )}
        <span className="flag-category__count">
          {visibleFlags.filter((f) => flagSelections[f.id]).length}/{visibleFlags.length}
        </span>
        <span className={`flag-category__chevron ${expanded ? 'flag-category__chevron--open' : ''}`}>
          ▶
        </span>
      </button>

      {expanded && (
        <div className="flag-category__body">
          {visibleFlags.map((flag) => (
            <FlagItem
              key={flag.id}
              flag={flag}
              value={flagSelections[flag.id]}
              onChange={(val) => onFlagChange(flag.id, val)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function FlagItem({ flag, value, onChange }) {
  const isActive = flag.type === 'boolean' ? value === true : Boolean(value);

  function handleBoolean() {
    onChange(value === true ? false : true);
  }

  function handleText(e) {
    onChange(e.target.value || false);
  }

  function handleNumber(e) {
    const v = e.target.value;
    onChange(v === '' ? false : v);
  }

  function handleSelect(e) {
    onChange(e.target.value || false);
  }

  return (
    <div className={`flag-item ${isActive ? 'flag-item--active' : ''} ${flag.requiresRoot ? 'flag-item--root' : ''}`}>
      {flag.type === 'boolean' ? (
        <label className="flag-item__row flag-item__row--checkbox" title={flag.description}>
          <input
            type="checkbox"
            checked={value === true}
            onChange={handleBoolean}
            className="flag-checkbox"
          />
          <span className="flag-item__flag-name">{flag.flag}</span>
          <span className="flag-item__label">{flag.name}</span>
          <div className="flag-item__badges">
            {flag.requiresRoot && <span className="badge badge--root badge--xs">ROOT</span>}
            {!flag.safe && <span className="badge badge--adv badge--xs">ADV</span>}
          </div>
        </label>
      ) : flag.type === 'select' ? (
        <label className="flag-item__row flag-item__row--select" title={flag.description}>
          <span className="flag-item__flag-name">{flag.flag}</span>
          <span className="flag-item__label">{flag.name}</span>
          <select
            value={value || ''}
            onChange={handleSelect}
            className="flag-select"
          >
            <option value="">— off —</option>
            {flag.options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      ) : flag.type === 'number' ? (
        <label className="flag-item__row flag-item__row--input" title={flag.description}>
          <span className="flag-item__flag-name">{flag.flag}</span>
          <span className="flag-item__label">{flag.name}</span>
          <div className="flag-item__badges">
            {flag.requiresRoot && <span className="badge badge--root badge--xs">ROOT</span>}
            {!flag.safe && <span className="badge badge--adv badge--xs">ADV</span>}
          </div>
          <input
            type="number"
            value={value || ''}
            onChange={handleNumber}
            placeholder={flag.placeholder}
            min={flag.min}
            max={flag.max}
            className="flag-input flag-input--number"
          />
        </label>
      ) : (
        // text
        <label className="flag-item__row flag-item__row--input" title={flag.description}>
          <span className="flag-item__flag-name">{flag.flag}</span>
          <span className="flag-item__label">{flag.name}</span>
          <div className="flag-item__badges">
            {flag.requiresRoot && <span className="badge badge--root badge--xs">ROOT</span>}
            {!flag.safe && <span className="badge badge--adv badge--xs">ADV</span>}
          </div>
          <input
            type="text"
            value={typeof value === 'string' ? value : ''}
            onChange={handleText}
            placeholder={flag.placeholder}
            className="flag-input"
            spellCheck={false}
          />
        </label>
      )}
      {isActive && flag.warning && (
        <div className="flag-item__warning">⚠ {flag.warning}</div>
      )}
      <div className="flag-item__desc">{flag.description}</div>
    </div>
  );
}
