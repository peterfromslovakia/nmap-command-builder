import React, { useState } from 'react';
import { CHEATSHEET } from '../data/cheatsheet';

export default function CheatsheetTab({ onLoadCommand }) {
  const [search, setSearch] = useState('');
  const [copiedCmd, setCopiedCmd] = useState(null);

  function handleCopy(cmd) {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedCmd(cmd);
      setTimeout(() => setCopiedCmd(null), 1500);
    });
  }

  const filtered = CHEATSHEET.map((section) => ({
    ...section,
    items: section.items.filter((item) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return item.command.toLowerCase().includes(q) || item.description.toLowerCase().includes(q);
    }),
  })).filter((section) => section.items.length > 0);

  return (
    <div className="cheatsheet-tab">
      <div className="cheatsheet-search-row">
        <span className="search-icon">⌕</span>
        <input
          className="search-input"
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search cheatsheet…"
          spellCheck={false}
        />
        {search && (
          <button className="search-clear" onClick={() => setSearch('')}>
            ✕
          </button>
        )}
      </div>

      {filtered.map((section) => (
        <div key={section.category} className="cheatsheet-section">
          <h3 className="cheatsheet-section__title">
            <span className="cheatsheet-section__bar" />
            {section.category}
          </h3>
          <table className="cheatsheet-table">
            <tbody>
              {section.items.map((item) => (
                <tr key={item.command} className="cheatsheet-row">
                  <td className="cheatsheet-cmd">
                    <code>{item.command}</code>
                  </td>
                  <td className="cheatsheet-desc">{item.description}</td>
                  <td className="cheatsheet-actions">
                    <button
                      className="btn btn--xs btn--copy"
                      onClick={() => handleCopy(item.command)}
                      title="Copy command"
                    >
                      {copiedCmd === item.command ? '✓' : '⎘'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {filtered.length === 0 && (
        <div className="no-results">No results for <em>"{search}"</em></div>
      )}
    </div>
  );
}
