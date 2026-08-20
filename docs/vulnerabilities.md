# Findings & Remediation Log

Target: [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) v20.2.0, vendored at [`juice-shop/`](../juice-shop), run via `bkimminich/juice-shop:v20.2.0` (Docker), listening on `http://localhost:3000`.

## Methodology

| Layer | Tool | Mode |
|---|---|---|
| DAST | OWASP ZAP (`zaproxy/zap-stable`, baseline scan) | Passive scan + spider against the running instance |
| SAST | Semgrep (`semgrep/semgrep`, `--config auto`) | Static analysis of `juice-shop/` source |

Both tools were run against the **unmodified** app first (baseline), then re-run after fixes (remediated), so results can be diffed. Raw output lives in [`docs/reports/baseline/`](reports/baseline) and `docs/reports/remediated/`.

## DAST — OWASP ZAP Baseline Scan

Run: `zap-baseline.py -t http://host.docker.internal:3000`
Result: **0 FAIL, 8 WARN, 59 PASS**. Full reports: [zap-baseline-report.html](reports/baseline/zap-baseline-report.html) / [zap-baseline-report.json](reports/baseline/zap-baseline-report.json).

| # | Finding | Risk | CWE | Count | Status |
|---|---|---|---|---|---|
| 1 | Content Security Policy (CSP) Header Not Set | Medium | CWE-693 | 4 | Open |
| 2 | Cross-Domain Misconfiguration (permissive CORS) | Medium | CWE-264 | 2 | Open |
| 3 | Cross-Origin-Embedder-Policy Header Missing | Low | CWE-693 | 5 | Open |
| 4 | Cross-Origin-Opener-Policy Header Missing | Low | CWE-693 | 5 | Open |
| 5 | Dangerous JS Functions in use (`main.js`) | Low | CWE-749 | 1 | Open |
| 6 | Deprecated `Feature-Policy` header (should be `Permissions-Policy`) | Low | CWE-16 | 5 | Open |
| 7 | Timestamp Disclosure (Unix epoch in `styles.css`) | Low | CWE-497 | 5 | Open |
| 8 | Modern Web Application (informational — spidering note) | Info | — | 5 | N/A |

### Detail & planned fix

**1–4: Missing/weak security headers (CSP, CORS, COEP, COOP).**
Juice Shop's Express server (`app.ts` / `server.ts`) does not set a restrictive `Content-Security-Policy`, scopes CORS too broadly, and omits `Cross-Origin-Embedder-Policy` / `Cross-Origin-Opener-Policy`. Fix: add `helmet()` middleware (or explicit header configuration) with a locked-down CSP (`default-src 'self'`, no `unsafe-inline`/`unsafe-eval` where avoidable), restrict CORS to known origins, and set `Cross-Origin-Embedder-Policy: require-corp` / `Cross-Origin-Opener-Policy: same-origin`.

**5: Dangerous JS function in `main.js`.**
ZAP flags use of `eval`/`innerHTML`-style sinks in the bundled Angular app. Fix: locate and replace the flagged sink with a safe DOM API or sanitize input first (Angular's `DomSanitizer` where HTML injection is required).

**6: Deprecated `Feature-Policy` header.**
Server still emits the old header name. Fix: replace with `Permissions-Policy` (helmet v6+ does this automatically).

**7: Timestamp disclosure.**
A Unix timestamp is exposed in `styles.css` (likely a cache-busting build artifact, low risk but worth suppressing/confirming non-sensitive).

## SAST — Semgrep

Run: `semgrep --config auto juice-shop/`
Result: **68 findings** (18 ERROR, 45 WARNING, 3 INFO, 2 MEDIUM) across 408 rules / 1020 files. Full report: [semgrep-baseline.json](reports/baseline/semgrep-baseline.json).

Findings split into two groups: **application code** (the actual Express/Angular app — real remediation targets) and **infra/CI config** (Terraform + GitHub Actions files bundled in the upstream repo — out of scope for this app-focused remediation, listed for completeness).

### Application-code findings (remediation targets)

| # | Rule | File:Line | Severity | Notes |
|---|---|---|---|---|
| 1 | `express-sequelize-injection` | [routes/login.ts:34](../juice-shop/routes/login.ts#L34) | ERROR | Raw SQL built from user-controlled email/password in login — classic SQL injection (intentional Juice Shop "Login Admin" challenge). **Fixed:** switched to Sequelize named `replacements` instead of string interpolation. |
| 2 | `express-sequelize-injection` | [routes/search.ts:23](../juice-shop/routes/search.ts#L23) | ERROR | Product search query built via string concatenation — SQL injection. **Fixed:** switched to Sequelize named `replacements` instead of string interpolation. |
| 3 | `remote-property-injection` | [routes/currentUser.ts:31](../juice-shop/routes/currentUser.ts#L31) | ERROR | User-controlled property used to index/assign an object — prototype-pollution-adjacent injection risk. |
| 4 | `code-string-concat` / `eval-detected` | [routes/userProfile.ts:65](../juice-shop/routes/userProfile.ts#L65) | ERROR / WARNING | User profile "name" rendered via string concatenation into a template that gets evaluated — the classic Juice Shop stored-XSS-via-eval challenge. Same line also flagged by ZAP's "Dangerous JS Functions" DAST finding. |
| 5 | `eval-detected` | [routes/captcha.ts:22](../juice-shop/routes/captcha.ts#L22) | WARNING | `eval()` used to evaluate CAPTCHA answer. |
| 6 | `hardcoded-hmac-key` (×2) | [lib/insecurity.ts:42](../juice-shop/lib/insecurity.ts#L42), [lib/insecurity.ts:150](../juice-shop/lib/insecurity.ts#L150) | WARNING | Hardcoded HMAC keys used for hashing — should be loaded from environment/secret store. |
| 7 | `hardcoded-jwt-secret` | [lib/insecurity.ts:54](../juice-shop/lib/insecurity.ts#L54) | WARNING | JWT signing secret hardcoded in source (private key file is also committed under `encryptionkeys/`) — allows forging tokens. |
| 8 | `express-res-sendfile` (×4) | [routes/fileServer.ts:32](../juice-shop/routes/fileServer.ts#L32), [routes/keyServer.ts:14](../juice-shop/routes/keyServer.ts#L14), [routes/logfileServer.ts:14](../juice-shop/routes/logfileServer.ts#L14), [routes/quarantineServer.ts:14](../juice-shop/routes/quarantineServer.ts#L14) | WARNING | `res.sendFile()` with user-influenced path — path traversal risk if not strictly sanitized/allow-listed. |
| 9 | `path-join-resolve-traversal` | [lib/antiCheat.ts:196](../juice-shop/lib/antiCheat.ts#L196) | WARNING | Path built via `path.join`/`resolve` with untrusted input. |
| 10 | `express-open-redirect` | [routes/redirect.ts:18](../juice-shop/routes/redirect.ts#L18) | WARNING | Redirect target taken from request without allow-list validation. |
| 11 | `express-check-directory-listing` (×5) | [server.ts:268,288,292,296,300](../juice-shop/server.ts#L268) | WARNING | Multiple `express.static()` mounts without directory-listing disabled. |
| 12 | `unknown-value-with-script-tag` | [routes/videoHandler.ts:71](../juice-shop/routes/videoHandler.ts#L71) | WARNING | Unescaped value interpolated where a `<script>` tag context expects sanitization — XSS risk. |
| 13 | `template-explicit-unescape` | [views/promotionVideo.pug:75](../juice-shop/views/promotionVideo.pug#L75) | WARNING | Pug template explicitly disables auto-escaping (`!=`) for a value — XSS risk if that value is user-influenced. |
| 14 | `prototype-pollution-loop` | [frontend/src/hacking-instructor/helpers/helpers.ts:49](../juice-shop/frontend/src/hacking-instructor/helpers/helpers.ts#L49) | WARNING | `for...in` loop copying properties without an `own-property` guard — prototype pollution pattern. |
| 15 | `detect-non-literal-regexp` (×2) | [lib/codingChallenges.ts:76,78](../juice-shop/lib/codingChallenges.ts#L76) | WARNING | RegExp built from non-literal (potentially user-influenced) input — ReDoS risk. |
| 16 | `unsafe-formatstring` | [server.ts:157](../juice-shop/server.ts#L157) | INFO | Format string built with non-constant input. |
| 17 | `detected-generic-secret` | [data/static/users.yml:151](../juice-shop/data/static/users.yml#L151) | ERROR | Secret-shaped string in static seed data — expected here (seed/demo data), verify not reused as a real credential. |

### Infra / CI findings (out of scope for app remediation, listed for completeness)

- `github-actions-mutable-action-tag` ×7 — GitHub Actions pinned to mutable tags (e.g. `@v4`) instead of a commit SHA.
- `run-shell-injection` ×5, `gha-curl-pipe-shell` ×1 — CI workflow steps that interpolate untrusted input into shell commands, or pipe `curl` output to a shell.
- `aws-elb-access-logs-not-enabled` ×5, `aws-subnet-has-public-ip-address` ×5, `insecure-load-balancer-tls-version` ×5, `aws-cloudwatch-log-group-unencrypted` ×2 — Terraform configs (example/reference infra bundled in the repo, not deployed by this project).
- `npm-missing-minimum-release-age` ×2 — dependency-freshness policy findings, not vulnerabilities per se.
- `detected-jwt-token` ×3 (in `*.spec.ts` test files) — example JWTs used as test fixtures, not live secrets.
- `detect-replaceall-sanitization` ×2 (in `data/static/codefixes/*`) and the two `express-sequelize-injection` hits in `data/static/codefixes/*` — these are Juice Shop's own **bundled challenge solutions/exercises** (intentionally vulnerable/fixed code samples shown to players), not the app's live code path.

### Known limitation: RSN (Refactoring Safety Net)

Several fixed lines (e.g. `login.ts:34`, `search.ts:23`) sit inside Juice Shop's own `// vuln-code-snippet` blocks, which back its in-app coding challenges and are checked for consistency against `data/static/codefixes/*` via `npm run rsn`. This project has no local Node/npm toolchain (Docker-only), so that check has not been run — fixing these vulnerabilities is expected to intentionally break the corresponding CTF challenges (e.g. "Login Admin", "Union SQL Injection"), which is out of scope for this security-remediation exercise but worth knowing if you also care about Juice Shop's own challenge suite staying playable.

## Before / After Summary

| Metric | Baseline | Remediated |
|---|---|---|
| ZAP FAIL | 0 | — |
| ZAP WARN | 8 | — |
| ZAP PASS | 59 | — |
| Semgrep ERROR | 18 | — |
| Semgrep WARNING | 45 | — |
| Semgrep total | 68 | — |

_(Filled in after remediation + re-scan.)_
