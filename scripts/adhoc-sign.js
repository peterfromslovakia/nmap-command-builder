// electron-builder afterPack hook: ad-hoc podpis macOS aplikacie.
//
// Bez Apple Developer ID certifikatu electron-builder podpisovanie preskoci a
// v balicku ostane len ciastocny podpis Electron binarky. macOS na Apple Silicon
// potom stiahnutu aplikaciu oznaci ako "poskodenu". Ad-hoc podpis celeho .app
// to opravi — macOS ju potom berie ako aplikaciu od neovereneho vyvojara, ktoru
// je mozne povolit v Nastaveniach → Sukromie a bezpecnost → "Aj tak otvorit".
//
// Ak je k dispozicii skutocny certifikat (CSC_LINK), electron-builder po tomto
// kroku aplikaciu podpise nim a ad-hoc podpis prepise.
const { execFileSync } = require('child_process');
const path = require('path');

exports.default = async function adhocSign(context) {
  if (context.electronPlatformName !== 'darwin') return;
  const app = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
  execFileSync('codesign', ['--force', '--deep', '--sign', '-', app], { stdio: 'inherit' });
  execFileSync('codesign', ['--verify', '--deep', '--strict', app], { stdio: 'inherit' });
  console.log(`  • ad-hoc signed  ${app}`);
};
