import React from 'react';
import { useT } from '../i18n/ui';

const mb = (bytes) => (bytes ? ` · ${Math.round(bytes / 1e6)} MB` : '');

/** Pruh "Nova verzia je dostupna" — stiahnutie otvori prehliadac. */
export default function UpdateBanner({ update, onDownload, onLater, onDisableAuto }) {
  const t = useT();
  return (
    <div className="update-banner" role="status">
      <span className="update-banner__text">
        ⬆ <b>{t('Version {v}', { v: update.latest })}</b> {t('is available (you have {v}).', { v: update.current })}
      </span>
      <span className="update-banner__actions">
        {update.asset && (
          <button className="btn btn--xs btn--primary" onClick={() => onDownload(update.asset.url)} title={update.asset.name}>
            ↓ {t('DOWNLOAD')}{mb(update.asset.size)}
          </button>
        )}
        <button className="btn btn--xs" onClick={() => onDownload(update.pageUrl)}>{t("WHAT'S NEW")}</button>
        <button className="btn btn--xs btn--ghost" onClick={onLater}>{t('LATER')}</button>
        <button className="link-btn update-banner__off" onClick={onDisableAuto}>{t("don't check automatically")}</button>
      </span>
    </div>
  );
}
