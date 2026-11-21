import React, { useMemo, useState } from 'react';
import { NSE_SCRIPTS, NSE_SCRIPT_MAP, NSE_CATEGORIES, DANGEROUS_CATEGORIES } from '../data/nseScripts';
import { parseList } from '../utils/nseSelection';

const RISK_LABEL = { safe: 'SAFE', intrusive: 'INTRUSIVE', dangerous: 'ADV' };

function isAdvOnly(name) {
  if (DANGEROUS_CATEGORIES.has(name)) return true;
  return NSE_SCRIPT_MAP[name]?.risk === 'dangerous';
}

export default function ScriptsTab({
  scriptValue,
  scriptArgsValue,
  advancedMode,
  onToggleScript,
  onAddScriptArg,
  onRemoveScripts,
  onClearScripts,
}) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');

  const selected = useMemo(() => parseList(scriptValue), [scriptValue]);
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const argKeys = useMemo(
    () => new Set(parseList(scriptArgsValue).map((x) => x.split('=')[0].trim())),
    [scriptArgsValue]
  );

  const visibleCategories = NSE_CATEGORIES.filter(
    (c) => advancedMode || !DANGEROUS_CATEGORIES.has(c.id)
  );

  const visibleScripts = useMemo(() => {
    const q = query.trim().toLowerCase();
    return NSE_SCRIPTS.filter((x) => {
      if (!advancedMode && x.risk === 'dangerous') return false;
      if (category !== 'all' && !x.categories.includes(category)) return false;
      if (!q) return true;
      return (
        x.name.includes(q) ||
        x.service.includes(q) ||
        x.description.toLowerCase().includes(q)
      );
    });
  }, [query, category, advancedMode]);

  const hiddenAdv = !advancedMode ? selected.filter(isAdvOnly) : [];

  return (
    <div className="scripts-tab">
      <p className="presets-intro">
        Click a script or category to add it to <code>--script</code>. Scripts run against
        open ports, so combine them with a port scan; most also need <code>-sV</code>.
        Only run scripts against hosts you are authorized to test.
      </p>

      {/* Selection summary */}
      <div className="scripts-selection">
        <span className="scripts-selection__label">--script</span>
        {selected.length === 0 ? (
          <span className="scripts-selection__empty">nothing selected</span>
        ) : (
          selected.map((name) => (
            <button
              key={name}
              className={`script-chip ${isAdvOnly(name) ? 'script-chip--adv' : ''}`}
              onClick={() => onToggleScript(name)}
              title="Remove"
            >
              {name} ×
            </button>
          ))
        )}
        {selected.length > 0 && (
          <button className="scripts-selection__clear" onClick={onClearScripts}>
            CLEAR
          </button>
        )}
      </div>

      {hiddenAdv.length > 0 && (
        <div className="scripts-warning">
          ⚠ Selected in ADV mode and still active: {hiddenAdv.join(', ')}.{' '}
          <button className="link-btn" onClick={() => onRemoveScripts(hiddenAdv)}>
            Remove them
          </button>
        </div>
      )}

      {/* Categories */}
      <div className="scripts-section-title">CATEGORIES</div>
      <div className="scripts-categories">
        {visibleCategories.map((c) => (
          <button
            key={c.id}
            className={`script-cat ${selectedSet.has(c.id) ? 'script-cat--active' : ''} ${
              DANGEROUS_CATEGORIES.has(c.id) ? 'script-cat--adv' : c.id === 'intrusive' ? 'script-cat--warn' : ''
            }`}
            onClick={() => onToggleScript(c.id)}
            title={c.description}
          >
            {c.id}
          </button>
        ))}
      </div>

      {/* Filter */}
      <div className="scripts-filter">
        <input
          className="search-input"
          type="text"
          placeholder="Search scripts, services (http, smb, ssh…)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          spellCheck={false}
        />
        <select
          className="flag-select"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          title="Filter by category"
        >
          <option value="all">all categories</option>
          {visibleCategories.map((c) => (
            <option key={c.id} value={c.id}>{c.id}</option>
          ))}
        </select>
      </div>

      {/* Script list */}
      <div className="scripts-list">
        {visibleScripts.length === 0 && (
          <div className="scripts-selection__empty">No scripts match.</div>
        )}
        {visibleScripts.map((x) => {
          const active = selectedSet.has(x.name);
          return (
            <div
              key={x.name}
              className={`script-card script-card--${x.risk} ${active ? 'script-card--active' : ''}`}
            >
              <button className="script-card__main" onClick={() => onToggleScript(x.name)}>
                <div className="script-card__header">
                  <span className="script-card__check">{active ? '■' : '□'}</span>
                  <code className="script-card__name">{x.name}</code>
                  <span className="script-card__service">{x.service}</span>
                  <span className={`script-risk script-risk--${x.risk}`}>{RISK_LABEL[x.risk]}</span>
                </div>
                <p className="script-card__desc">{x.description}</p>
                <div className="script-card__cats">{x.categories.join(' · ')}</div>
              </button>
              {x.args.length > 0 && (
                <div className="script-card__args">
                  {x.args.map((a) => (
                    <button
                      key={a.key}
                      className="script-arg"
                      disabled={argKeys.has(a.key)}
                      onClick={() => {
                        if (!active) onToggleScript(x.name);
                        onAddScriptArg(a.key, a.example);
                      }}
                      title={a.description}
                    >
                      + {a.key}={a.example}
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
