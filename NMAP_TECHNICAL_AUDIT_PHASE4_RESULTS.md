# NMAP_TECHNICAL_AUDIT — Phase 4 Results
**Project:** nmap-command-builder  
**Version after Phase 4:** 1.12.0 (from 1.11.1)  
**Audit date:** 2026-11-22  
**Base commit:** d0c1a4b (v1.11.1)  
**Evaluated by:** Claude Sonnet 4.6  
**Independent evaluation target:** GPT-6 / external reviewer

---

## 1. Summary Table

| Finding | Priority | Status | Test method |
|---------|----------|--------|-------------|
| F-001 — Port state accuracy | P1 | **PASS** | REAL (7 new Jest tests) |
| F-002 — Bundled nmap data files | P1 | **PASS (CI)** | SIMULATED — code change verified, installer NOT built |
| F-003 — LIKELY vs CONFIRMED confidence | P2 | **PASS** | REAL (5 new Jest tests) |
| F-004 — NSE error diagnostics | P2 | **PASS** | REAL (5 new Jest tests) |
| F-005 — Security model validation | P2 | **PASS** | REAL (`elevate.test.js` + code inspection) |
| F-006 — React component tests | P2 | **NOT RUN** | `@testing-library/react` not installed; deferred |
| F-007 — Hybrid XML evaluation | P3 | **NOT RUN** | Design proposal only — not implemented |

---

## 2. F-001 — Port State Accuracy

### Root cause (confirmed)
`RE_PORT` in `src/utils/report.js:12` only captures `open` and `open|filtered` states. When a port transitions `open → filtered`, it disappears from the open list and had no entry in the new scan's data — leading `diffScans()` to incorrectly classify it as `closedPorts`.

### Key nmap fact
Nmap shows `filtered` ports in text output by default. It does NOT show `closed` ports (they are suppressed). This means:
- Port absent from new scan's output + same port range → assume `closed`
- Port absent from new scan's output + different port range → `notTestedPorts`
- Port present in new scan as `filtered`/`closed|filtered` → `filteredPorts`

### Changes made

**`src/utils/report.js`**
- Added `RE_PORT_ALL` (line ~13): captures all states including `filtered`, `closed`, `closed|filtered`, `unfiltered`
- Added `export function parseAllTestedPorts(text)`: returns `{ [hostKey]: { [portKey]: state } }` — called once per snapshot, stored as `allPortStates`

**`src/utils/scanDiff.js`**
- `makeSnapshot()`: added `allPortStates: parseAllTestedPorts(text)` field
- `diffScans()`: moved `portRangeDiffers` computation to top; replaced flat `closedPorts` loop with logic that checks `currAllStates[portKey]` and routes to `filteredPorts[]`, `closedPorts[]`, or `notTestedPorts[]`
- Return value: added `filteredPorts`, `notTestedPorts`; `total` updated to include both

**`src/components/DiffPanel.jsx`**
- Added two `<Section>` components after CLOSED PORTS: `FILTERED PORTS` (tone `info`) and `NOT TESTED PORTS` (tone `info`)

**`src/i18n/report.js`** — `changeSections()` now includes entries for `Filtered ports` / `Filtrované porty` and `Not tested ports` / `Netestované porty`

**`src/i18n/uiSk.js`** — added `'FILTERED PORTS': 'FILTROVANÉ PORTY'` and `'NOT TESTED PORTS': 'NETESTOVANÉ PORTY'`

### Test evidence (REAL)

File: `src/utils/scanDiff.test.js`, describe block `port state accuracy (F-001)`

| Test | Assertion | Result |
|------|-----------|--------|
| `open → filtered` → filteredPorts | `filteredPorts` contains port 80; `closedPorts` does not | **PASS** |
| `open → closed\|filtered` → filteredPorts | `filteredPorts` contains port 80 | **PASS** |
| `open → closed` (explicit) → closedPorts | `closedPorts` contains port 80; `filteredPorts` does not | **PASS** |
| `open → absent, same portSpec` → closedPorts | `closedPorts` contains port 80; `notTestedPorts` does not | **PASS** |
| `open → absent, different portSpec` → notTestedPorts | `notTestedPorts` contains ports 80 and 443 | **PASS** |
| `allPortStates` stored correctly | states for `open`, `filtered`, `closed` all present | **PASS** |
| `total` includes all arrays | sum formula matches | **PASS** |

```
npm test --testPathPattern="scanDiff" → 26 tests, 0 failures
```

### Backward compatibility
Old snapshots in localStorage lack `allPortStates`. Guard `(curr.allPortStates || {})[key] || {}` prevents crash.

---

## 3. F-002 — Bundled Nmap Data Files

### Root cause (confirmed)
CI workflow (`release.yml`) previously copied only the nmap binary:
```bash
cp "$(which nmap)" extraResources/bin/nmap
```
Nmap data files (`scripts/`, `nselib/`, `nmap-services`, `nmap-os-db`, etc.) were NOT bundled. NSE scripts fail to load on systems where nmap is not separately installed.

**Measured data dir size:** ~23 MB at `/opt/homebrew/opt/nmap/share/nmap/`  
**Key files:** `scripts/` (550+ .nse files), `nselib/`, `nmap-services`, `nmap-os-db`, `nmap-service-probes`, `nmap-protocols`, `nmap-rpc`, `nmap-mac-prefixes`, `nmap-payloads`, `nse_main.lua`

### Changes made

**`.github/workflows/release.yml`**
- macOS: `cp -r "$(brew --prefix nmap)/share/nmap" extraResources/share/`
- Linux: `cp -r /usr/share/nmap extraResources/share/`
- Windows (PowerShell): copies `scripts`, `nselib`, `nmap-services`, `nmap-os-db`, `nmap-service-probes`, `nmap-protocols`, `nmap-rpc`, `nmap-mac-prefixes`, `nmap-payloads`, `nse_main.lua` from `C:\Program Files (x86)\Nmap\`

**`package.json`**
- `extraResources`: added `{ "from": "extraResources/share", "to": "share" }`

**`electron/main.js`**
- Added `resolveNmapDataDir()`: checks `process.resourcesPath/share/nmap`
- In `nmap:run`: `NMAPDIR` set to bundled data dir in spawn env (both elevated and non-elevated)
- In `nmap:check`: returns `bundledDataDir` path for diagnostics

### Test method: **SIMULATED**

The CI change was code-reviewed and logic verified. A clean-room test (macOS without system nmap installed, using bundled binary + data) was **NOT RUN** — this would require a full installer build and clean VM. 

**What can be verified without a build:**
- `resolveNmapDataDir()` logic: returns `null` in dev mode (no `process.resourcesPath`) — correct
- `NMAPDIR` env variable: nmap respects this (documented behavior; not retested here)
- `extraResources` path: electron-builder places `share/` at `app.asar.unpacked/../share/` or `resources/share/` depending on config — the path `process.resourcesPath + '/share/nmap'` is consistent with how `bin/` is already found

**Remaining risk:** Windows installer not tested. PowerShell `Copy-Item -Recurse` behavior depends on which nmap version Chocolatey installs on the runner.

---

## 4. F-003 — Confidence Levels

### Root cause (confirmed)
`RE_VULNERABLE = /State: (LIKELY )?VULNERABLE/` matched both `State: VULNERABLE` and `State: LIKELY VULNERABLE` with no distinction. No `verificationStatus` field existed on findings.

### Changes made

**`src/utils/findings.js`**
- Replaced single regex with two inline checks:
  ```js
  const vulnerable = /State: VULNERABLE/.test(body);
  const likelyVulnerable = /State: LIKELY VULNERABLE/.test(body);
  ```
- Added `verificationStatus` to all findings:
  - `'CONFIRMED'` — `State: VULNERABLE` present
  - `'LIKELY'` — `State: LIKELY VULNERABLE` present (and `State: VULNERABLE` absent)
  - `'VERSION_MATCH'` — vulners script (CVE based on version match, not live test)
  - `'DETECTED'` — FINDING_RULES match without `requireVulnerable` (misconfiguration, risky port)
- Fixed guard: `rule.requireVulnerable && !vulnerable && !likelyVulnerable` — `LIKELY VULNERABLE` now also passes through (before it was silently dropped)
- Removed unused `RE_VULNERABLE` constant (lint fix)

**`src/components/FindingsPanel.jsx`**
- Added `LIKELY` badge (amber, `ver-badge--likely`) and `VER` badge (gray, `ver-badge--version`) in finding header after severity badge
- Tooltip text localized via `t()`

**`src/App.css`**
- Added `.ver-badge`, `.ver-badge--likely`, `.ver-badge--version` (6 CSS rules)

**`src/i18n/uiSk.js`**
- `'Likely vulnerable — not confirmed by live test': 'Pravdepodobne zraniteľné — nepotvrdené živým testom'`
- `'Based on version match, not a live exploit test': 'Na základe zhody verzie, nie živého testu'`

### Test evidence (REAL)

File: `src/utils/findings.test.js`, describe block `verificationStatus (F-003)`

| Test | Assertion | Result |
|------|-----------|--------|
| vulners → VERSION_MATCH | `v.verificationStatus === 'VERSION_MATCH'` | **PASS** |
| heartbleed (VULNERABLE) → CONFIRMED | `h.verificationStatus === 'CONFIRMED'` | **PASS** |
| smb-vuln-foo (LIKELY VULNERABLE) → LIKELY | `g.verificationStatus === 'LIKELY'` | **PASS** |
| ftp-anon → DETECTED | `ftp.verificationStatus === 'DETECTED'` | **PASS** |
| LIKELY does not change severity | `g.severity === 'high'` | **PASS** |

---

## 5. F-004 — NSE Error Diagnostics

### Root cause (confirmed)
Lines matching `| ERROR: ...` or `| NSE: ...` share the same `|_` / `| ` prefix as script headers. `RE_SCRIPT_HEAD = /^\|[_ ]([a-z0-9][\w.-]*):(.*)$/i` matched `|_ERROR:` before the error check ran, causing silent discard.

### Changes made

**`src/utils/findings.js`**
- Added `RE_NSE_ERROR = /^\|[_ ]\s*(ERROR|NSE):\s*(.+)$/i`
- Added `export function parseNseErrors(text)`: walks the same line-by-line structure as `splitScriptBlocks`, tracks host/port/script context, pushes `{ host, port, script, error }` entries
- **Critical fix:** NSE error check runs BEFORE script head check in `parseNseErrors()` — otherwise `|_ERROR:` matches `RE_SCRIPT_HEAD` first

**`src/components/FindingsPanel.jsx`**
- Added `nseErrors` prop
- Renders `<div className="nse-errors">` section after the findings list when `nseErrors.length > 0`
- Each row shows: script name (cyan monospace), port (if applicable), error message

**`src/App.css`** — added `.nse-errors`, `.nse-errors__title`, `.nse-error-row`, `.nse-error-row__script`, `.nse-error-row__port`, `.nse-error-row__msg`

**`src/App.js`**
- Import: `parseNseErrors` from `./utils/findings`
- Added `const nseErrors = useMemo(...)` after `findings` memo
- Passed `nseErrors={nseErrors}` to `<FindingsPanel>`

**`src/i18n/uiSk.js`** — `'NSE ERRORS ({n})': 'CHYBY NSE ({n})'`

**`src/utils/report.js`** — `buildReportModel()` now includes `nseErrors: parseNseErrors(text)` in the returned model

### Test evidence (REAL)

File: `src/utils/findings.test.js`, describe block `parseNseErrors (F-004)`

| Test | Assertion | Result |
|------|-----------|--------|
| Port-level ERROR captured | `script === 'http-vuln-cve2014-3704'`, error matches `/Script execution failed/` | **PASS** |
| NSE: prefix captured | `script === 'ssh-vuln'`, error matches `/failed to connect/` | **PASS** |
| Host-level ERROR captured | `script === 'smb2-security-mode'`, `port === null` | **PASS** |
| Clean output returns `[]` | `parseNseErrors(SAMPLE).toEqual([])` | **PASS** |
| Errors don't affect finding count | no finding with `id === 'nse_error'` | **PASS** |

---

## 6. F-005 — Security Model Validation

### Phase 3 conclusion revisited
Phase 3 found: `spawn(shell: false)` prevents shell injection; NSE file access in non-elevated mode is equivalent to user running nmap directly; elevated guard correctly blocks file paths.

### Evidence (REAL — from existing test suite)

File: `electron/elevate.test.js` (50 tests, all PASS via `npm run test:main`)

Relevant passing tests:
- `validateElevatedArgs rejects --script containing a path` → confirmed at commit d0c1a4b, still passes
- `validateElevatedArgs rejects --script-args with ; & | chars` → confirmed
- `nmap:run builds spawn call without shell: true` → confirmed in `main.js` line 412: `spawn(cmd, cmdArgs, { stdio: ..., env })` — no `shell` option

**Phase 3 security conclusions remain valid.** No changes in this phase affect the security boundary.

**New addition (F-004 interaction):** `parseNseErrors()` only reads stdout; it does not execute anything. NSE error messages are displayed verbatim — this is acceptable because nmap's stdout is already trusted (it comes from our own spawned process, not user input or network).

---

## 7. F-006 — React Component Tests

### Status: NOT RUN

**Reason:** `@testing-library/react` is not installed (not hoisted from `react-scripts` devDependencies in this Node version). Installing it requires `npm install --save-dev @testing-library/react @testing-library/jest-dom @testing-library/user-event` and writing `src/components/components.test.jsx`.

**Planned test coverage (deferred to v1.13.0):**
1. FindingsPanel renders LIKELY badge when `verificationStatus === 'LIKELY'`
2. FindingsPanel renders VER badge when `verificationStatus === 'VERSION_MATCH'`
3. FindingsPanel renders NSE errors section when `nseErrors` prop non-empty
4. FindingsPanel returns null when `scanStatus === 'crashed'` / `'idle'`
5. DiffPanel renders FILTERED PORTS section when `diff.filteredPorts.length > 0`
6. DiffPanel renders NOT TESTED PORTS section
7. SK locale: component renders Slovak strings when `lang='sk'`

---

## 8. F-007 — Hybrid XML Approach (Design Proposal)

### Status: NOT IMPLEMENTED — design only

**Problem F-007 addresses:** Text-based nmap output has ambiguities. XML output (`nmap -oX`) provides exact port states, timing, and service data.

**Proposed approach:**
```bash
nmap -oX /tmp/ncb-{id}.xml -oN - [args...]
#          ^ XML to file         ^ text to stdout (for live display)
```
After scan completion:
1. Parse XML for exact port states (using Node's `DOMParser` or `xml2js`)
2. Replace text-parsed port data in `makeSnapshot()` with XML data
3. Clean up temp file on exit

**Benefits:**
- F-001 fully solved: `closed`/`filtered`/`unfiltered` exact from XML
- More accurate service/version parsing
- OS detection data accessible

**Cost:**
- XML parser dependency (or native DOMParser — available in Electron renderer, not in main process)
- Temp file management + cleanup on crash
- 1–2 week implementation effort
- Text output still needed for live streaming (XML is complete-document, not streaming)

**Decision:** Not implemented in Phase 4. F-001 is adequately addressed by `parseAllTestedPorts()` for the common cases. Hybrid XML remains a future improvement for v2.x.

---

## 9. Test Run Summary

```
npm test -- --watchAll=false
  Test Suites: 22 passed, 22 total
  Tests:       348 passed, 348 total  (+17 new vs v1.11.1)
  Time:        ~1.3 s

npm run test:main
  tests 50 / pass 50 / fail 0

npm run lint
  0 errors, 0 warnings
```

**New tests added in Phase 4:**

| File | Describe block | Count |
|------|---------------|-------|
| `src/utils/scanDiff.test.js` | `port state accuracy (F-001)` | 7 |
| `src/utils/findings.test.js` | `verificationStatus (F-003)` | 5 |
| `src/utils/findings.test.js` | `parseNseErrors (F-004)` | 5 |

---

## 10. Files Changed

| File | Change summary |
|------|----------------|
| `src/utils/report.js` | +`RE_PORT_ALL`, +`parseAllTestedPorts()`, +`changeSections` entries for filtered/notTested |
| `src/utils/scanDiff.js` | +`allPortStates` in snapshot, +`filteredPorts[]`, +`notTestedPorts[]` in diff, `portRangeDiffers` moved to top |
| `src/utils/findings.js` | +`verificationStatus` on all findings, +`parseNseErrors()`, removed unused `RE_VULNERABLE`, NSE error check before script head check |
| `src/components/FindingsPanel.jsx` | +`nseErrors` prop, +NSE errors section, +LIKELY/VER badges |
| `src/components/DiffPanel.jsx` | +FILTERED PORTS section, +NOT TESTED PORTS section |
| `src/App.css` | +`.ver-badge` styles, +`.nse-errors` styles |
| `src/App.js` | +`parseNseErrors` import, +`nseErrors` memo, +`nseErrors` prop on FindingsPanel |
| `src/i18n/report.js` | +EN/SK entries for `Filtered ports`, `Not tested ports` |
| `src/i18n/uiSk.js` | +6 new SK translations (FILTERED PORTS, NOT TESTED PORTS, CHYBY NSE, ver-badge tooltips) |
| `src/i18n/uiI18n.test.js` | +`FILTERED PORTS`, `NOT TESTED PORTS` to hardcoded used-strings list |
| `src/utils/scanDiff.test.js` | +7 F-001 tests |
| `src/utils/findings.test.js` | +5 F-003 tests, +5 F-004 tests |
| `.github/workflows/release.yml` | +nmap data dir bundling for macOS, Linux, Windows |
| `package.json` | +extraResources `share/`, version 1.11.1 → 1.12.0 |
| `electron/main.js` | +`resolveNmapDataDir()`, +NMAPDIR in spawn env, +`bundledDataDir` in nmap:check |
| `CHANGELOG.md` | +v1.12.0 entry |
| `README.md` | test count 331 → 348 |

---

## 11. Remaining Risks

1. **F-002 (Windows installer):** PowerShell bundling script untested; nmap data dir layout may differ across Chocolatey versions
2. **F-006 (component tests):** 0% React component coverage; LIKELY/VER badge rendering, NSE errors section, filtered port sections not covered by automated tests
3. **F-007 (XML accuracy):** `closed` ports still not reliably captured — nmap suppresses them in text output; XML would solve this definitively
4. **NSE errors in report output:** `parseNseErrors()` data is included in `buildReportModel()` but the markdown/HTML report templates do not yet render the NSE errors appendix section

---

## 12. Questions for Independent Evaluation

1. **F-001:** Is the heuristic "port absent from text output + same port range = assume closed" valid across all nmap scan types (`-sT`, `-sU`, `-sF`, `-sX`)? UDP scans show `open|filtered` by default for untested ports — does this affect classification?

2. **F-002:** `NMAPDIR` is set to the bundled path unconditionally when it exists. If a user also has a system nmap installed, will the bundled data dir override their system version? Is this desirable?

3. **F-003:** Should `LIKELY VULNERABLE` findings receive a reduced CVSS score or severity downgrade? Currently severity is preserved from the rule/CVE score. The badge signals lower confidence, but the severity badge still shows `HIGH`/`CRITICAL`.

4. **F-004:** NSE error messages are displayed verbatim from nmap stdout. Is there an XSS risk if nmap embeds attacker-controlled data (e.g., from a banner grab) in an error message? The app uses React's JSX string rendering — does that provide sufficient escaping?

5. **F-007:** At what point does cumulative text-parsing complexity justify switching to hybrid XML? The current approach handles the most common cases but has known gaps for UDP states and `closed` port detection.
