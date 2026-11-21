// Validacia argumentov nmapu v main procese (posledna obranna vrstva).
// Renderer nie je doveryhodny: aj ked UI posle nieco ine, prejde len whitelist.

// Povolene prepinace nmapu = presne tie, ktore pozna UI (src/data/flags.js).
// Akykolvek iny prepinac (--datadir, --resume, --script-args-file, ...) sa
// zahodi v main procese, aj keby ho renderer poslal.
const ALLOWED_FLAGS = new Set([
  '-iL', '--exclude', '-Pn', '-sL', '-sn', '-n', '--traceroute',
  '-sS', '-sT', '-sU', '-sA', '-sN', '-sF', '-sX',
  '-p', '-F', '--top-ports', '-p-',
  '-sV', '--version-intensity', '--version-light', '--version-all',
  '-O', '--osscan-limit', '--osscan-guess',
  '-sC', '--script', '--script-args',
  '--min-rate', '--max-rate', '--max-retries', '--host-timeout',
  '-v', '-vv', '--open', '--reason', '-oN', '-oX', '-oG', '--stats-every',
  '-A', '-f', '--mtu', '-D', '-S', '--spoof-mac', '--data-length', '--badsum',
  '-sI', '-b', '--proxies',
]);
const ATTACHED_FLAG_RES = [/^-P[SAU][\d,-]*$/, /^-T[0-5]$/];
const SCRIPT_VALUE_RE = /^[A-Za-z0-9_,*.+() -]+$/; // nazvy/kategorie, nie cesty

// Povolene znaky pre --script-args: key=value páry oddelené čiarkou.
// Zakazuje lomky (cesty k súborom) a ďalšie nebezpečné vzory.
// Príklad povolených hodnôt: "mincvss=5.0", "vulners.showall=true,http.useragent=Mozilla"
const SCRIPT_ARGS_RE = /^[A-Za-z0-9_.=,@: -]+$/;

function validateArgs(args) {
  if (!Array.isArray(args) || args.length === 0 || args.length > 64) {
    return 'Invalid argument format.';
  }
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (typeof a !== 'string' || a.length === 0 || a.length > 1024) return 'Invalid argument format.';
    // eslint-disable-next-line no-control-regex -- riadiace znaky su zamerne zakazane
    if (/[\u0000-\u001f\u007f]/.test(a)) return 'Invalid characters in argument.';
    if (a.startsWith('-')) {
      if (!ALLOWED_FLAGS.has(a) && !ATTACHED_FLAG_RES.some((re) => re.test(a))) {
        return `Flag not allowed: "${a}"`;
      }
      if (a === '--script') {
        const v = args[i + 1];
        if (typeof v !== 'string' || !SCRIPT_VALUE_RE.test(v)) {
          return '--script accepts only script names/categories, not file paths.';
        }
      }
      if (a === '--script-args') {
        const v = args[i + 1];
        if (typeof v !== 'string' || !SCRIPT_ARGS_RE.test(v)) {
          return '--script-args accepts only key=value pairs, not file paths.';
        }
      }
    }
  }
  return null;
}

module.exports = { validateArgs, ALLOWED_FLAGS, SCRIPT_VALUE_RE, SCRIPT_ARGS_RE };
