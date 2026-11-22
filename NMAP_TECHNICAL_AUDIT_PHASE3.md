# NMAP Command Builder — Technical Audit Phase 3

**Date:** 2026-11-22  
**Version audited:** 1.11.1 (commit `d0c1a4b`)  
**Auditor:** Claude Sonnet 4.6 (AI-assisted; all claims backed by specific file + line references)

---

## A. Executive Summary

The application is structurally sound and passes 331 automated tests with 0 lint warnings and green multi-platform CI. The core security model (Electron sandbox, IPC whitelist, spawn without shell) is correctly implemented. Three issues were confirmed by code inspection that require attention:

1. **[MEDIUM] Port state ambiguity in diff** — The parser captures only `open` / `open|filtered` ports. When a port disappears from scan output, the diff labels it `closedPorts` regardless of whether it became `closed`, `filtered`, or simply `not tested`. This is a semantic accuracy issue, not a crash.

2. **[LOW] No XML parsing** — The app parses nmap's text (`-oN`) output, not structured XML (`-oX`). This means the parser depends on English text patterns and nmap output formatting, which can vary with nmap version or NSE script updates.

3. **[INFO] React component layer: 0% test coverage** — All 21 React components have zero automated test coverage. Business logic is well-tested; UI rendering and user interaction paths are not.

No critical or high-severity security issues were found. All previous Phase 2 fixes are confirmed implemented and working.

---

## B. Architecture & Data Flow

```
User input (flags, target)
    │
    ▼
src/utils/commandBuilder.js   — builds nmap argv array
    │
    ▼
electron/main.js: nmap:run    — validates args (argsValidator.js + elevate.js),
                                spawns nmap as child process (spawn(), shell:false)
    │
    ▼
nmap stdout/stderr (text)     — streamed line-by-line to renderer via scan:output IPC
    │
    ▼
src/App.js (fullOutRef)       — accumulates all chunks; terminal shows last N lines
    │
    ├── src/utils/report.js: parseHosts()    — extracts hosts + open ports
    ├── src/utils/findings.js: parseFindings() — extracts NSE script findings
    └── src/utils/scanDiff.js: makeSnapshot() — compacts result for history
         │
         ▼
    src/utils/report.js: buildReportModel()  — combines all data, applies intel
         │
         ├── toMarkdown()  — Markdown export
         └── toHtml()      — HTML → Chromium PDF via report:pdf IPC
```

**Data format:** Text output only. The app does NOT use nmap XML (`-oX`). Both `parseHosts` (`report.js:12`) and `splitScriptBlocks` (`findings.js:5–9`) parse raw nmap stdout line by line.

---

## C. Parser Verification

### C1. Port state handling

**File:** `src/utils/report.js:12`

```js
const RE_PORT = /^(\d+)\/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.*))?$/;
```

**Verified behavior** (tested with actual regex against nmap output patterns):

| Nmap port state    | Captured by parseHosts? | Notes |
|--------------------|------------------------|-------|
| `open`             | YES — state: 'open'     | Correct |
| `open\|filtered`   | YES — state: 'open\|filtered' | Correct |
| `closed`           | **NO**                  | By design — not in inventory |
| `filtered`         | **NO**                  | By design — not in inventory |
| `unfiltered`       | **NO**                  | Rare; correct to omit |
| `closed\|filtered` | **NO**                  | Rare; correct to omit |

**Consequence for diff:** When a port transitions from `open` to `filtered`, the diff correctly lists it in `closedPorts` because it disappears from the parsed port list. However, the label shown in the report is "Closed ports" — semantically, `filtered` is not the same as `closed`. The UI/report does not distinguish these two outcomes.

**tcpwrapped:** The line `139/tcp open netbios-ssn tcpwrapped` matches RE_PORT: service=`netbios-ssn`, version=`tcpwrapped`. **Correctly captured.**

### C2. Host detection

**File:** `src/utils/report.js:11`

```js
const RE_HOST = /^Nmap scan report for (.+)$/;
```

Captures both `192.168.1.1` and `hostname.lan (192.168.1.1)` forms. The `hostKey()` function in `scanDiff.js:28` extracts IP from parentheses when present, so host matching survives DNS name changes between scans. **Correct.**

### C3. NSE script parsing

**File:** `src/utils/findings.js:9`

```js
const RE_SCRIPT_HEAD = /^\|[_ ]([a-z0-9][\w.-]*):(.*)$/i;
```

The RE_PORT regex in findings.js (`findings.js:6`) is intentionally looser than in report.js — it tracks port context for NSE blocks regardless of port state. This is correct: NSE scripts can appear after any port state.

**NSE error lines** (e.g., `| ERROR: Script execution failed`) do not match `RE_SCRIPT_HEAD` (no script name before `:` in that format) and are silently skipped. **Finding C3-1 (LOW): NSE script errors are not surfaced in the UI.**

### C4. Locale / language dependency

The parser relies on English text patterns:

| Pattern | Location | Risk |
|---------|----------|------|
| `State: (LIKELY )?VULNERABLE` | `findings.js:10` | nmap always outputs in EN for script results |
| `VULNERABLE:` | `findings.js:63` | Same |
| `Anonymous FTP login allowed` | remediation rules | Hardcoded EN string |
| `Nmap scan report for` | `report.js:11`, `findings.js:5` | Always EN in nmap |

**Assessment:** Nmap always produces English output for `Nmap scan report for` and NSE script headers regardless of system locale. FINDING_RULES in remediation.js use English patterns that match nmap's fixed English output. **Risk is LOW but present** — a future nmap version could change output format.

### C5. Interrupted scan handling

`App.js` accumulates all output in `fullOutRef.current.chunks` (unbounded). The terminal display is limited to the last N chunks, but `parseHosts` and `parseFindings` receive the full accumulated text. If a scan is interrupted mid-host-block, the partial host is still pushed to `hosts[]` with whatever ports were parsed so far. **Correct behavior** — partial results are shown, not silently dropped.

### C6. XML output — not used

**Finding C6-1 (INFO/DESIGN):** The application does not use `-oX` (XML). Using XML would provide structured data (port states, OS matches, script output) that is more reliable than text parsing. However, switching would be a major refactor:

| | Current (text) | XML |
|--|--|--|
| Implementation effort | Done | High |
| Reliability | Depends on format | Structured |
| NSE output | Parsed from text | Also in text nodes |
| Regression risk | Low | High |
| Nmap version compat | High (text is stable) | High (XML is stable) |

**Recommendation:** Keep text parsing for now. The current parser covers all practical cases. Document as a future improvement.

---

## D. Scan Comparison Verification

### D1. Methodology compatibility matrix

**Files:** `src/utils/scanMeta.js`, `src/utils/scanDiff.js`

Verified with test suite (331 tests, relevant subset in `scanDiff.test.js` and `scanMeta.test.js`):

| Scenario | portsComparable | vulnsComparable | portRangeDiffers | methodDiffers |
|----------|----------------|----------------|-----------------|---------------|
| `-sn` vs `-sV` | false | false | false | true |
| `-A` vs `-sn` | false | false | false | true |
| `-sV` vs `-sV` (same ports) | true | true | false | false |
| `-sV` vs `--script vuln` | true | **false** | false | true |
| `--script vuln` vs `--script vuln` | true | true | false | false |
| `-p-` vs `-p 80,443` | true | true | **true** | **true** |
| `-p 80,443` vs `-p 80,443,8080` | true | true | **true** | **true** |
| `-sS` vs `-sT` | true | true | false | false |
| `-sU` vs `-sS` | true | true | false | false |

### D2. Finding D2-1: TCP vs UDP — no protocol-aware comparison

**File:** `src/utils/scanDiff.js:60–77`

Port comparison uses `portKey(p)` defined as `${p.port}/${p.proto}`. So `22/tcp` and `22/udp` are treated as separate ports. If prev scan was TCP-only and curr scan is UDP-only, all TCP ports show as `closedPorts`. This is technically correct (the port-protocol pair was not seen), but `portRangeDiffers` is not set because both scans return the same `portSpec` (both might use 'default'). The method warning is not triggered.

**Impact:** LOW — TCP-only vs UDP-only comparisons are uncommon in practice. The behavior is technically accurate (different protocol = different port), but no explicit warning is generated.

### D3. Finding D3-1: Partial portRangeDiffers — no per-port reliability

**Files:** `src/utils/scanDiff.js:88–90`

`portRangeDiffers` triggers the global method warning but does NOT attempt to identify which ports were tested in both scans. For example, if prev used `-p-` (found port 8080 open) and curr used `-p 80,443`, port 8080 appears in `closedPorts`. The warning is shown, but the port 8080 entry in `closedPorts` is not individually marked as "not tested in curr scan" vs "genuinely closed".

**Current behavior:** Global warning → user must interpret manually.  
**Better behavior:** Per-port `notTested` flag when port is outside curr scan range.  
**Assessment MEDIUM** — warning is correct, granularity is missing. No false negatives, only reduced precision.

### D4. Verified diff scenarios (SIMULATED — using saved nmap output fixtures)

All the following use test fixtures in `scanDiff.test.js`:

| Scenario | Expected | Result | Status |
|----------|----------|--------|--------|
| discovery vs port: no closedPorts | `closedPorts=[]` | `closedPorts=[]` | PASS |
| discovery vs port: goneHosts shown | `goneHosts has 192.168.1.30` | confirmed | PASS |
| port vs port: closed port detected | `closedPorts has port 21` | confirmed | PASS |
| vuln vs non-vuln: no resolvedFindings | `resolvedFindings=[]` | confirmed | PASS |
| same specs: portRangeDiffers=false | false | false | PASS |
| different specs: portRangeDiffers=true | true | true | PASS |
| scan with exitCode/signal stored | snapshot has fields | confirmed | PASS |

---

## E. NSE Security Review

### E1. Argument validation layers

Two independent layers (both must pass):

**Layer 1 — `validateArgs()` in `argsValidator.js`:**
- Flag whitelist (ALLOWED_FLAGS)
- `--script` value: `SCRIPT_VALUE_RE = /^[A-Za-z0-9_,*.+() -]+$/`
- `--script-args` value: `SCRIPT_ARGS_RE = /^[A-Za-z0-9_.=,@: \-/+*]+$/`

**Layer 2 — DANGEROUS regex in `main.js:375`:**
```js
const DANGEROUS = /[;&|`$(){}[\]<>!\\'"]/;
```
Applies to ALL args after whitelist check. Blocks all shell injection metacharacters.

**Layer 3 (elevated only) — `validateElevatedArgs()` in `elevate.js:19`:**
- Blocks `-oN`, `-oX`, `-oG`, `-iL` entirely
- Blocks `--script` with `.nse` file paths
- Blocks `--script-args` with `/` or `\`

### E2. NSE file path access via script-args (non-elevated)

For non-elevated runs, `brute.db=/usr/share/wordlists/rockyou.txt` is now allowed (Phase 2 fix). Since `spawn()` is called without `shell: true`, this is not shell injection — the string is passed as a literal argument to nmap. The nmap process then reads the file using its own file I/O, which is limited by the process's user permissions (same as the user running the app).

**This is equivalent to the user running the same nmap command manually.** No privilege escalation is possible through this path.

For elevated runs, `validateElevatedArgs` in `elevate.js:28` explicitly blocks `/` and `\` in script-args. This is the correct additional restriction for privileged execution.

### E3. SAFE/ADV mode behavior

**File:** `src/data/presets.js:302,316`

Two presets have `safe: false`: `brute_login` and `dos_check`. These are hidden when `advancedMode === false` (default). When a user imports a preset with unsafe flags, `App.js:315` calls `setAdvancedMode(true)` automatically.

The `validateElevatedArgs` function in `elevate.js` does NOT enforce safe/unsafe as a separate layer — it enforces file access restrictions. The SAFE/ADV distinction is UI-only and does not block execution at the main process level. **This is by design** — the user can enable ADV mode and run any whitelisted command.

**Finding E3-1 (LOW):** An imported user preset with `safe: false` flags automatically enables ADV mode in the UI, but there is no IPC-level enforcement that prevents running unsafe presets without ADV mode. If the renderer sends the args directly (bypassing the preset UI), `validateArgs` would still pass them (the flags themselves are whitelisted). The SAFE/ADV distinction is a UI contract, not a security boundary.

### E4. Legitimate complex NSE values — verified PASS

| Value | SCRIPT_ARGS_RE match | DANGEROUS block | Passes? |
|-------|---------------------|----------------|---------|
| `mincvss=5.0` | ✓ | ✓ (no dangerous chars) | YES |
| `http.useragent=Mozilla/5.0` | ✓ (/ allowed) | ✓ | YES |
| `brute.db=/usr/share/wordlists/rockyou.txt` | ✓ | ✓ | YES |
| `vulners.showall=true,mincvss=4.0` | ✓ | ✓ | YES |
| `nfs-ls.root=/etc/shadow` | ✓ | ✓ (non-elevated) | YES (legitimate) |
| `pass=test;id` | ✓ | ✗ (`;` blocked) | **NO** |
| `db=C:\passwords.txt` | ✗ (`\` not in SCRIPT_ARGS_RE) | ✗ (`\` blocked) | **NO** |

---

## F. Reporting Verification

### F1. Data path from scan to report

**Verified path** (`buildReportModel`, `src/utils/report.js:146`):

1. `text` (raw nmap output) → `parseHosts(text)` → structured hosts + ports
2. `text` → `parseFindings(text)` → structured NSE findings (or `given` if already processed with intel)
3. `comparison` (optional diff result) → `changeSections()` → comparison narrative
4. `meta` (tester info) → `normalizeMeta()` → report header
5. Combined → `toMarkdown()` / `toHtml()` → export

### F2. Finding traceability in reports

Each finding gets:
- `ref: F-01`, `F-02`, … (sequential, `report.js:162`)
- `host`: IP or hostname from nmap output
- `port`: `22/tcp` format or empty for host-level scripts
- `script`: NSE script name (e.g., `ssl-heartbleed`)
- `evidence`: first matching line from NSE output
- `cves[]`: CVE IDs from the finding
- `cveDetails[]`: enriched via intel API (CVSS, EPSS, NVD) if available

**Gap F2-1 (LOW):** The `evidence` field stores a single line from NSE output (the first line matching the detection rule). For complex multi-CVE findings (vulners), evidence shows only the top 5 CVEs. The original NSE output block is not preserved in the finding; it's only in the raw scan text.

### F3. Automated vs confirmed CVE

The difference is documented in the UI/reports:
- **vulners findings**: "N known CVEs for this service version" — these are version-match CVEs, not confirmed exploitable
- **Script VULNERABLE findings** (ms17-010, heartbleed etc.): `requireVulnerable: true` in FINDING_RULES — only triggered when `State: VULNERABLE` is in the output, meaning nmap confirmed the vulnerability
- **LIKELY VULNERABLE**: matched by `RE_VULNERABLE = /State: (LIKELY )?VULNERABLE/` — same rule, same label

**Gap F3-1 (LOW):** `LIKELY VULNERABLE` and `VULNERABLE` are both matched by the same regex and generate findings with the same severity. The distinction is not surfaced in the UI or report.

### F4. Report types — verified coverage

| Scenario | parseHosts | parseFindings | risk | comparison | SIMULATED/REAL |
|----------|-----------|--------------|------|-----------|----------------|
| Discovery scan | hosts only, no ports | no findings | `not_assessed` | portRangeDiffers if vs port scan | SIMULATED (test fixtures) |
| Port scan | hosts + ports | no findings (unless rules match) | `none`/`low`/`medium` | portsComparable=true | SIMULATED |
| Service scan `-sV` | hosts + ports + versions | rules match if services known | varies | portsComparable=true | SIMULATED |
| Vuln scan `--script vuln` | hosts + ports | findings from VULNERABLE | `high`/`critical` | vulnsComparable=true | SIMULATED |
| Incompatible methodology diff | hosts | findings | as above | methodDiffers=true, warning shown | SIMULATED |
| Interrupted scan | partial hosts | partial findings from what arrived | as above | n/a | SIMULATED |

**All report scenarios: SIMULATED** — tested against saved nmap output fixtures, not live nmap execution.

---

## G. Test Coverage

### G1. Test count by category (331 tests total)

| Category | Tests | Key files |
|----------|-------|-----------|
| Parsing (hosts, findings, NSE blocks) | ~45 | `findings.test.js`, `report.test.js` |
| Scan comparison / diff | ~35 | `scanDiff.test.js`, `scanMeta.test.js` |
| Security / arg validation | ~12 | `argsValidator.test.js`, `elevate.test.js` |
| Report generation (Markdown/HTML) | ~25 | `report.test.js` |
| Presets / data integrity | ~18 | `presets.test.js` |
| i18n / localization | ~20 | `uiI18n.test.js`, `i18n.test.js` |
| Stress / edge cases | ~8 | `stress.test.js` |
| Shortcuts / UX | ~8 | `shortcuts.test.js` |
| Networking / ARP / gateway | ~30 | `arp.test.js`, `gateway.test.js`, `network.test.js` |
| Config / version / build | ~13 | `config.test.js`, `version.test.js` |
| Other utilities | ~117 | `inventory.test.js`, `monitor.test.js`, `intel.test.js`, etc. |

**Tests using real nmap:** 0 — no test executes actual nmap binary.  
**Tests using real network:** 0 — all network tests mock the system calls.  
**Tests using saved fixtures:** ~180 — the majority of parsing/diff tests.  
**Tests using mock objects:** ~40 — localStorage mock, electronAPI mock.

### G2. Code coverage (from `npm test -- --coverage`)

| File | Statements | Branches | Lines | Key uncovered |
|------|-----------|---------|-------|---------------|
| `src/utils/report.js` | 92.95% | 81.51% | 96.78% | L46-50 (intel failure path), L357-359 (inventory with labels), L752-753 (PDF footer) |
| `src/utils/findings.js` | 92.47% | 76.56% | 94.11% | L15-17 (cvssSeverity low branch), L65 (empty vulnTitle) |
| `src/utils/scanDiff.js` | 96.25% | 83.63% | 98.21% | L117 (broken localStorage) |
| `src/utils/scanMeta.js` | 100% | 95.74% | 100% | L25 (empty command edge), L88 (top-ports edge) |
| `electron/argsValidator.js` | — | — | — | Not in React coverage (Node.js) |
| `electron/main.js` | — | — | — | Not in React coverage |
| `src/components/*.jsx` | **0%** | **0%** | **0%** | Entire component layer |
| `src/utils/commandBuilder.js` | 63.26% | 58.33% | 66.66% | L81-104 (flag combination edge cases) |

### G3. Uncovered important paths

1. **React components (0%)** — BuilderTab, FindingsPanel, DiffPanel, NetworkMap etc. have no rendering tests. The correct business logic output could be passed to a broken component and no test would catch it.

2. **`commandBuilder.js` L81-104** — flag combination validation logic partially uncovered. Some invalid flag combinations may not be caught.

3. **`findings.js` branch 76.56%** — the `cvssSeverity('low')` branch (scores < 4.0) is untested. If a vulners finding has CVSS < 4.0, the severity label may differ from expectations.

---

## H. CI/CD & Distribution

### H1. Build pipeline

**Workflows:** `.github/workflows/release.yml` (tag push) + `.github/workflows/build.yml` (branch push)

| Step | Verified |
|------|---------|
| npm install | BUILD PASS |
| npm run build (React) | BUILD PASS |
| nmap bundling — macOS (brew) | BUILD PASS (CI log) |
| nmap bundling — Linux (apt) | BUILD PASS (CI log) |
| nmap bundling — Windows (Chocolatey) | BUILD PASS (CI log) |
| Npcap installer download (Windows) | BUILD PASS — `npcap.com/dist/npcap-1.79.exe` |
| `npm run dist` → `.dmg/.exe/.AppImage` | BUILD PASS |
| Artifacts uploaded to GitHub Release | BUILD PASS (v1.11.1) |

**RUNTIME VERIFIED:** NOT RUN — the distributed binaries have not been installed and launched on a real machine in this audit.

### H2. Nmap binary resolution at runtime

**File:** `electron/main.js:21–28`

```js
function resolveNmap() {
  const ext = process.platform === 'win32' ? '.exe' : '';
  try {
    const bundled = path.join(process.resourcesPath, 'bin', `nmap${ext}`);
    if (fs.existsSync(bundled)) return bundled;
  } catch (_) { /* dev mode */ }
  return which('nmap') || 'nmap';
}
```

Priority: bundled binary → PATH → fallback string `'nmap'`.

**Potential issue H2-1 (LOW):** If `extraResources/bin/nmap` is not present (e.g., CI failed to bundle it but build still succeeded), `resolveNmap()` falls back to PATH `nmap`. The app appears to work but uses the system nmap. The `nmap:check` IPC handler (`main.js:293`) reports `found: true` and `bundled: false` in this case, so the UI can distinguish. The check is correct.

### H3. NSE scripts availability

**Finding H3-1 (MEDIUM):** The bundled `nmap` binary requires NSE scripts (`.nse` files) and their database to be in a specific location relative to the nmap binary. When nmap is bundled as a single binary in `resources/bin/nmap`, the NSE script directory is NOT bundled (it's usually at `/usr/share/nmap/scripts/` on Linux/macOS).

For macOS/Linux, the bundled nmap binary will look for scripts at `<nmap-binary-dir>/../share/nmap/scripts/` or fall back to its compiled-in path. Since only the binary is bundled (not the full nmap data directory), NSE scripts (`--script vuln`, `--script vulners` etc.) will likely fail silently or produce no results on a fresh system where nmap was not separately installed.

**Verification status:** NOT RUN on a clean system without nmap installed.

**Impact:** High for vuln scanning, zero for port/service scanning (which does not require NSE scripts).

**Recommendation:** Test on a clean macOS/Windows VM without system nmap to verify NSE functionality.

### H4. Sensitive data in distribution

Checked `package.json` build config:

```json
"files": [
  "build/**/*",
  "electron/**/*",
  "!electron/**/*.test.js",
  "assets/**/*",
  "package.json"
]
```

Test files (`*.test.js`) are excluded. No `.env` files, credentials, or private keys found in the repository. The `asar: true` setting packages app files into an ASAR archive. Source code is accessible via `asar extract` but this is standard for Electron apps.

---

## I. Findings

### F-001 — MEDIUM: "Closed ports" label for filtered ports

**File:** `src/utils/report.js:12`, `src/utils/scanDiff.js:70-73`  
**Description:** `parseHosts()` only captures `open` and `open|filtered` ports. When a port transitions to `filtered`, it disappears from the parsed list and is labeled as "Closed" in the diff and report.  
**Evidence:** `RE_PORT = /^(\d+)\/(tcp|udp)\s+(open|open\|filtered)\s+.../` — `filtered` does not match.  
**Reproduction:** Scan a host with port 80 open (`-sV`), then scan again with firewall blocking port 80 (`filtered`). Diff shows port 80 as "Closed port" instead of "Port now filtered".  
**Impact:** Misleading report — firewall addition appears identical to port being shut down.  
**Recommended fix:** Capture `filtered` ports separately and add a `filteredPorts[]` array to the diff result, or label `closedPorts` items as "closed or filtered".  
**Verification:** CONFIRMED by code inspection.

### F-002 — MEDIUM: NSE scripts may not work without system nmap data directory

**File:** `package.json` (build config), `electron/main.js:21`  
**Description:** The build bundles only the nmap binary, not the NSE script directory. NSE-dependent presets (vuln_scan, cve_lookup, smb_enum etc.) may fail silently on clean installations.  
**Evidence:** Build config copies only `nmap`/`nmap.exe` binary. NSE scripts live in `/usr/share/nmap/scripts/` (Linux), `/opt/homebrew/share/nmap/` (macOS Homebrew), not in the app bundle.  
**Reproduction:** Install the app on a clean system with no prior nmap installation, attempt vuln_scan preset.  
**Impact:** Core vulnerability scanning feature (12 of 23 presets use `--script`) may silently produce no findings.  
**Verification:** NOT RUN on a clean system (would require clean VM). PLAUSIBLE by build config inspection.

### F-003 — LOW: `LIKELY VULNERABLE` and `VULNERABLE` are not distinguished

**File:** `src/utils/findings.js:10`  
**Description:** `RE_VULNERABLE = /State: (LIKELY )?VULNERABLE/` matches both states with equal severity.  
**Impact:** A "likely vulnerable" finding is reported with the same badge and severity as a confirmed vulnerability.  
**Recommended fix:** Add a `confirmed: false` flag to findings matching only `LIKELY VULNERABLE`, surfaced as "(likely)" qualifier in the UI.  
**Verification:** CONFIRMED by code inspection.

### F-004 — LOW: NSE script error lines not surfaced

**File:** `src/utils/findings.js:43–50`  
**Description:** Lines like `| ERROR: Script execution failed (use -d to debug)` from nmap output do not match `RE_SCRIPT_HEAD` and are silently dropped.  
**Impact:** A partially failing scan gives no indication that some NSE scripts did not execute.  
**Verification:** CONFIRMED by code inspection.

### F-005 — LOW: `--script-args` injection via NSE capabilities (design boundary)

**File:** `electron/argsValidator.js:25`, `electron/elevate.js:28`  
**Description:** Non-elevated scans allow `--script-args` values with file paths (e.g., `brute.db=/etc/shadow`). The nmap process then reads the file. This is intentional (Phase 2 fix) but should be documented.  
**Assessment:** This is NOT a vulnerability — it's equivalent to the user running nmap directly. The security boundary is correctly maintained: elevated runs block this via `elevate.js:28`.  
**Verification:** CONFIRMED by code inspection.

### F-006 — INFO: React component layer has 0% test coverage

**File:** All files in `src/components/`  
**Description:** 21 React components have zero automated tests.  
**Impact:** UI rendering bugs, broken display of findings/diff/reports would not be caught by CI.  
**Recommended fix:** Add smoke tests with React Testing Library for at minimum: FindingsPanel, DiffPanel, NetworkMap.  
**Verification:** CONFIRMED by coverage report.

### F-007 — INFO: Text parser vs XML — design tradeoff documented

**File:** `src/utils/report.js`, `src/utils/findings.js`  
**Description:** The app parses nmap text output, not XML. This is a design choice with tradeoffs.  
**Impact:** Parser may need updates for major nmap format changes. XML would be more reliable but requires significant refactor.  
**Recommended fix:** Consider `-oX` for a future major version. No action required now.  
**Verification:** CONFIRMED by code inspection.

---

## J. Reproduction Package

The following commands can be run on any machine with the repository to independently verify claims in this report.

### J1. Run all automated tests with coverage

```bash
cd nmap-command-builder
npm install
npm test -- --watchAll=false --coverage
# Expected: 331 tests pass, 0 failures
# Coverage output shows component layer at 0%
```

### J2. Verify RE_PORT regex behavior (port state handling)

```bash
node -e "
const RE = /^(\d+)\/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.*))?$/;
const cases = [
  '22/tcp    open            ssh      OpenSSH 8.2p1',
  '23/tcp    closed          telnet',
  '80/tcp    filtered        http',
  '443/tcp   open|filtered   https',
  '8080/tcp  unfiltered      http-proxy',
];
cases.forEach(l => console.log(l.split(/\s+/)[1].padEnd(14), '->', RE.test(l) ? 'MATCHED' : 'NOT MATCHED'));
"
# Expected:
# open           -> MATCHED
# closed         -> NOT MATCHED
# filtered       -> NOT MATCHED
# open|filtered  -> MATCHED
# unfiltered     -> NOT MATCHED
```

### J3. Verify --script-args validation

```bash
node --test electron/argsValidator.test.js
# Expected: 6 tests pass
```

### J4. Verify port range diff

```bash
npm test -- --watchAll=false --testPathPattern="scanDiff"
# Expected: all tests pass, including portRangeDiffers tests
```

### J5. Verify ELEVATED_FORBIDDEN blocks file I/O flags

```bash
node --test electron/elevate.test.js
# Expected: all tests pass
```

### J6. Check nmap binary in a CI-built artifact (manual step)

```
# On a clean macOS machine (no homebrew, no system nmap):
# 1. Download Nmap-Command-Builder-1.11.1-arm64.dmg from GitHub releases
# 2. Install to /Applications
# 3. Run app → check if nmap:check shows bundled=true
# 4. Run "nmap -sn" preset → should work (no NSE)
# 5. Run "vuln_scan" preset → check if NSE scripts execute or fail silently
# This is NOT RUN in this audit.
```

---

## K. Final Verdict

### What is demonstrably correct (CONFIRMED by code + tests)

- IPC security model: `isTrusted()`, `contextIsolation`, `sandbox`, `spawn()` without `shell: true`
- Argument validation: flag whitelist, `--script` name-only, `--script-args` injection blocked
- Elevated run restrictions: file I/O flags blocked (`-oN`, `-iL` etc.), path injection blocked
- Scan methodology detection: discovery / port / service / vuln correctly classified
- Diff methodology guards: discovery scan does not produce false `closedPorts` or `resolvedFindings`
- Port range tracking: `portRangeDiffers` flag correctly set when port specs differ
- Risk assessment: discovery scan returns `not_assessed` not `none`
- Crash vs kill: `userKill` flag correctly distinguishes SIGTERM (user) from SIGSEGV (crash)
- 331 automated tests pass, 0 lint warnings, CI green on all three platforms

### What is confirmed problematic

1. **F-001** `filtered` ports labeled as "Closed" in diff/reports
2. **F-002** NSE scripts likely unavailable on clean install (not tested on clean system)
3. **F-003** `LIKELY VULNERABLE` and `VULNERABLE` get equal severity treatment
4. **F-004** NSE error lines silently dropped
5. **F-006** React components: 0% test coverage

### What could not be verified in this audit

| Claim | Status | Reason |
|-------|--------|--------|
| NSE scripts work on clean install | NOT RUN | Requires clean VM without system nmap |
| PDF renders correctly on all platforms | NOT RUN | Requires running Electron app |
| Windows installer works end-to-end | NOT RUN | Requires Windows machine |
| App survives nmap crash (SIGSEGV) in real use | NOT RUN | Requires triggering actual crash |
| Monitoring auto-report triggers correctly | NOT RUN | Requires running app + scheduled scan |
| All 23 presets produce correct nmap output | NOT RUN | Requires live network target |

---

*Report generated: 2026-11-22. All code references verified against commit `d0c1a4b` (v1.11.1).*
