import React from 'react';
import { FLAG_CATEGORIES } from '../data/flags';
import { validateTarget } from '../utils/validator';
import FlagCategory from './FlagCategory';

// Viac rozhrani v tej istej sieti (napr. Wi-Fi + Ethernet) = jedno tlacidlo.
function groupNetworks(networks) {
  const map = new Map();
  for (const n of networks) {
    const g = map.get(n.suggested) || { suggested: n.suggested, virtual: true, members: [] };
    g.members.push(n);
    g.virtual = g.virtual && n.virtual;
    map.set(n.suggested, g);
  }
  return Array.from(map.values());
}

export default function BuilderTab({
  target,
  onTargetChange,
  networks = [],
  onUseNetwork,
  onRefreshNetworks,
  flagSelections,
  onFlagChange,
  advancedMode,
  searchQuery,
  onSearchChange,
  expandedCategories,
  onToggleCategory,
}) {
  const targetResult = target ? validateTarget(target) : null;
  const targetError = targetResult && !targetResult.valid ? targetResult.error : null;

  // Filter categories that have any visible flags
  const visibleCategories = FLAG_CATEGORIES.filter((cat) => {
    if (!cat.safe && !advancedMode) return false;
    return cat.flags.some((f) => {
      if (!f.safe && !advancedMode) return false;
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return (
        f.name.toLowerCase().includes(q) ||
        f.flag.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q)
      );
    });
  });

  return (
    <div className="builder-tab">
      {/* Target input */}
      <div className="builder-target">
        <label className="target-label">
          <span className="target-label__text">TARGET</span>
          <span className="target-label__hint">IP · CIDR · hostname · range</span>
        </label>
        <div className={`target-input-wrap ${targetError ? 'target-input-wrap--error' : ''}`}>
          <span className="target-input__prefix">&gt;</span>
          <input
            className="target-input"
            type="text"
            value={target}
            onChange={(e) => onTargetChange(e.target.value)}
            placeholder="192.168.1.1 or 10.0.0.0/24 or hostname"
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
          />
        </div>
        {targetError && <div className="target-error">⚠ {targetError}</div>}

        {/* Detected local networks */}
        <div className="net-detect">
          <span className="net-detect__label">
            {networks.length > 0 ? 'DETECTED NETWORK' : 'NO NETWORK DETECTED'}
          </span>
          {groupNetworks(networks).map((g) => (
            <button
              key={g.suggested}
              type="button"
              className={`net-chip ${target === g.suggested ? 'net-chip--active' : ''} ${g.virtual ? 'net-chip--virtual' : ''}`}
              onClick={() => onUseNetwork && onUseNetwork(g.suggested)}
              title={g.members.map((m) => `${m.iface}: you are ${m.address} (network ${m.cidr})`).join('\n')}
            >
              {g.members.map((m) => m.iface).join(' + ')} · {g.suggested}
              <span className="net-chip__ip"> (you {g.members.map((m) => m.address).join(', ')})</span>
            </button>
          ))}
          <button
            type="button"
            className="net-chip net-chip--refresh"
            onClick={() => onRefreshNetworks && onRefreshNetworks()}
            title="Re-detect network"
          >
            ⟳
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="builder-search">
        <span className="search-icon">⌕</span>
        <input
          className="search-input"
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search flags…"
          spellCheck={false}
        />
        {searchQuery && (
          <button className="search-clear" onClick={() => onSearchChange('')}>
            ✕
          </button>
        )}
      </div>

      {/* Flag categories */}
      <div className="builder-flags">
        {visibleCategories.length === 0 ? (
          <div className="no-results">
            No flags match <em>"{searchQuery}"</em>
          </div>
        ) : (
          visibleCategories.map((cat) => (
            <FlagCategory
              key={cat.id}
              category={cat}
              flagSelections={flagSelections}
              onFlagChange={onFlagChange}
              advancedMode={advancedMode}
              searchQuery={searchQuery}
              expanded={!!expandedCategories[cat.id]}
              onToggle={() => onToggleCategory(cat.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}
