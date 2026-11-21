// ─── Spustenie nmapu s pravami spravcu (bez Terminalu) ───────────────────────
//
//  macOS  — sudo -A: heslo si vypyta systemove okno (osascript) cez SUDO_ASKPASS.
//           Heslo ide priamo do sudo, aplikacia ho nevidi ani neuklada.
//  Linux  — sudo -A s grafickym oknom (zenity / kdialog), inak pkexec (polkit).
//  Windows — netreba: nmap pouziva Npcap a raw skeny funguju bez spravcu.
//
// Ako root moze nmap citat a zapisovat subory kdekolvek, preto pre beh s pravami
// spravcu plati prisnejsia kontrola argumentov (ziadne subory, ziadne cesty).

const fs = require('fs');
const path = require('path');

/** Prepinace, ktore pracuju so subormi — pri behu ako root su zakazane. */
const ELEVATED_FORBIDDEN = new Set(['-oN', '-oX', '-oG', '-iL']);
const SCRIPT_NAME_RE = /^[A-Za-z0-9_,*+() -]+$/; // bez bodky → ziadne .nse subory

/** null = v poriadku, inak text chyby. Doplna (nenahradza) validateArgs. */
function validateElevatedArgs(args) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (ELEVATED_FORBIDDEN.has(a)) return `${a} is not allowed when running as administrator (it reads or writes files).`;
    if (a === '--script' && !SCRIPT_NAME_RE.test(String(args[i + 1] || ''))) {
      return 'As administrator, --script accepts only script names and categories from the library.';
    }
    if (a === '--script-args' && /[/\\]/.test(String(args[i + 1] || ''))) {
      return 'As administrator, --script-args must not contain file paths.';
    }
  }
  return null;
}

/** Absolutna cesta k programu z PATH (sudo / pkexec PATH pouzivatela nepreberaju). */
function which(name, envPath = process.env.PATH || '', exists = (p) => {
  try { fs.accessSync(p, fs.constants.X_OK); return fs.statSync(p).isFile(); } catch (_) { return false; }
}) {
  for (const dir of envPath.split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    const p = path.join(dir, name);
    if (exists(p)) return p;
  }
  return null;
}

/**
 * Ako ziskat prava spravcu na tomto systeme.
 * @returns {{ method: 'sudo-askpass'|'pkexec', helper?: string }|null}
 */
function elevationMethod(platform = process.platform, find = (n) => which(n)) {
  if (platform === 'darwin') return find('sudo') || fs.existsSync('/usr/bin/sudo') ? { method: 'sudo-askpass', helper: 'osascript' } : null;
  if (platform === 'linux') {
    if (find('sudo')) {
      if (find('zenity')) return { method: 'sudo-askpass', helper: 'zenity' };
      if (find('kdialog')) return { method: 'sudo-askpass', helper: 'kdialog' };
    }
    if (find('pkexec')) return { method: 'pkexec' };
  }
  return null;
}

/** Obsah pomocneho skriptu pre SUDO_ASKPASS; text vyzvy cita z NCB_PROMPT. */
function askpassScript(helper) {
  if (helper === 'osascript') {
    return `#!/bin/sh
exec /usr/bin/osascript \\
  -e 'activate' \\
  -e 'set p to system attribute "NCB_PROMPT"' \\
  -e 'set r to display dialog p default answer "" with hidden answer with title "Nmap Command Builder" with icon caution buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel"' \\
  -e 'text returned of r' 2>/dev/null
`;
  }
  if (helper === 'zenity') return '#!/bin/sh\nexec zenity --password --title="Nmap Command Builder" --text="$NCB_PROMPT" 2>/dev/null\n';
  if (helper === 'kdialog') return '#!/bin/sh\nexec kdialog --title "Nmap Command Builder" --password "$NCB_PROMPT" 2>/dev/null\n';
  throw new Error(`Unknown askpass helper: ${helper}`);
}

/** Zapise pomocny skript do priecinka aplikacie (len pre pouzivatela, 0700). */
function writeAskpass(dir, helper) {
  const file = path.join(dir, `askpass-${helper}.sh`);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, askpassScript(helper), { mode: 0o700 });
  fs.chmodSync(file, 0o700);
  return file;
}

/**
 * Prikaz na spustenie nmapu ako spravca.
 * @returns {{ cmd: string, args: string[], env: object }}
 */
function elevatedCommand({ method, nmapPath, args, askpass, prompt, env = process.env }) {
  if (!nmapPath || !path.isAbsolute(nmapPath)) throw new Error('nmap not found');
  if (method === 'sudo-askpass') {
    return {
      cmd: 'sudo',
      args: ['-A', '-p', '', '--', nmapPath, ...args],
      env: { ...env, SUDO_ASKPASS: askpass, NCB_PROMPT: prompt },
    };
  }
  if (method === 'pkexec') return { cmd: 'pkexec', args: [nmapPath, ...args], env };
  throw new Error(`Unknown elevation method: ${method}`);
}

const MESSAGES = {
  en: {
    notAdmin: 'This user account is not an administrator.',
    noPassword: 'Administrator password was not entered — the scan did not run.',
    unavailable: 'Running as administrator is not available on this system.',
  },
  sk: {
    notAdmin: 'Tento používateľský účet nie je správca.',
    noPassword: 'Heslo správcu nebolo zadané — sken sa nespustil.',
    unavailable: 'Spustenie s právami správcu nie je v tomto systéme dostupné.',
  },
};
const msg = (lang, key) => (MESSAGES[lang] || MESSAGES.en)[key];

/** Bezne hlasky sudo/pkexec → kratke vysvetlenie v jazyku aplikacie. */
function explainElevationError(text, lang = 'en') {
  const s = String(text || '');
  if (/not in the sudoers|is not allowed to run sudo/i.test(s)) return msg(lang, 'notAdmin');
  if (/no password was provided|incorrect password attempts|a password is required|Request dismissed|Not authorized/i.test(s)) {
    return msg(lang, 'noPassword');
  }
  return null;
}

module.exports = {
  validateElevatedArgs, which, elevationMethod, askpassScript, writeAskpass, elevatedCommand, explainElevationError,
  ELEVATED_FORBIDDEN, msg,
};
