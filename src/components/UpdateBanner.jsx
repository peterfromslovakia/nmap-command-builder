import React from 'react';

const mb = (bytes) => (bytes ? ` · ${Math.round(bytes / 1e6)} MB` : '');

/** Pruh "Nova verzia je dostupna" — stiahnutie otvori prehliadac. */
export default function UpdateBanner({ update, onDownload, onLater, onDisableAuto }) {
  return (
    <div className="update-banner" role="status">
      <span className="update-banner__text">
        ⬆ <b>Version {update.latest}</b> is available (you have {update.current}).
      </span>
      <span className="update-banner__actions">
        {update.asset && (
          <button className="btn btn--xs btn--primary" onClick={() => onDownload(update.asset.url)} title={update.asset.name}>
            ↓ DOWNLOAD{mb(update.asset.size)}
          </button>
        )}
        <button className="btn btn--xs" onClick={() => onDownload(update.pageUrl)}>WHAT&apos;S NEW</button>
        <button className="btn btn--xs btn--ghost" onClick={onLater}>LATER</button>
        <button className="link-btn update-banner__off" onClick={onDisableAuto}>don&apos;t check automatically</button>
      </span>
    </div>
  );
}
