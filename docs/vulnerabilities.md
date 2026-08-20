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
| 1 | Content Security Policy (CSP) Header Not Set | Medium | CWE-693 | 4 | **Fixed** |
| 2 | Cross-Domain Misconfiguration (permissive CORS) | Medium | CWE-264 | 2 | **Fixed** |
| 3 | Cross-Origin-Embedder-Policy Header Missing | Low | CWE-693 | 5 | **Fixed** |
| 4 | Cross-Origin-Opener-Policy Header Missing | Low | CWE-693 | 5 | **Fixed** |
| 5 | Dangerous JS Functions in use (`main.js`) | Low | CWE-749 | 1 | Open (frontend bundle, out of scope — see note) |
| 6 | Deprecated `Feature-Policy` header (should be `Permissions-Policy`) | Low | CWE-16 | 5 | **Fixed** |
| 7 | Timestamp Disclosure (Unix epoch in `styles.css`) | Low | CWE-497 | 5 | Open (low-risk build artifact — see note) |
| 8 | Modern Web Application (informational — spidering note) | Info | — | 5 | N/A |

### Detail & fix

**1–4, 6: Missing/weak security headers (CSP, CORS, COEP, COOP, deprecated Feature-Policy).**
`server.ts` previously used `cors()` with no options (reflects any Origin — functionally allows every origin), only `helmet.noSniff()`/`helmet.frameguard()` (no CSP, no COEP/COOP), and the deprecated `feature-policy` package. **Fixed:** CORS restricted to `config.get('server.baseUrl')`; added `helmet.contentSecurityPolicy()` with a policy permissive enough to keep the existing Angular frontend working (`'self'` plus `'unsafe-inline'`/`'unsafe-eval'` where the app currently relies on them — a maximally strict policy would need a full frontend audit this project doesn't have tooling to run, see [known limitations](#known-limitations)); added `helmet.crossOriginEmbedderPolicy()` / `helmet.crossOriginOpenerPolicy()`; replaced the `feature-policy` middleware with a `Permissions-Policy` header. All in `server.ts`.

**5: Dangerous JS function in `main.js`.**
This is a minified/bundled frontend production build artifact, not source — the actual source location isn't directly editable here (no local Node/npm toolchain to rebuild the Angular bundle and verify the fix, see [known limitations](#known-limitations)). Left open; a real fix would locate the flagged sink in `frontend/src/` and rebuild.

**7: Timestamp disclosure.**
A Unix timestamp in `styles.css` (a generated build artifact, not source-controlled). Cosmetic/low-risk — no sensitive data, just a cache-busting value — and not source-editable without a frontend rebuild (same tooling limitation as #5). Left open.

## SAST — Semgrep

Run: `semgrep --config auto juice-shop/`
Result: **68 findings** (18 ERROR, 45 WARNING, 3 INFO, 2 MEDIUM) across 408 rules / 1020 files. Full report: [semgrep-baseline.json](reports/baseline/semgrep-baseline.json).

Findings split into two groups: **application code** (the actual Express/Angular app — real remediation targets) and **infra/CI config** (Terraform + GitHub Actions files bundled in the upstream repo — out of scope for this app-focused remediation, listed for completeness).

### Application-code findings (remediation targets)

| # | Rule | File:Line | Severity | Notes |
|---|---|---|---|---|
| 1 | `express-sequelize-injection` | [routes/login.ts:34](../juice-shop/routes/login.ts#L34) | ERROR | Raw SQL built from user-controlled email/password in login — classic SQL injection (intentional Juice Shop "Login Admin" challenge). **Fixed:** switched to Sequelize named `replacements` instead of string interpolation. |
| 2 | `express-sequelize-injection` | [routes/search.ts:23](../juice-shop/routes/search.ts#L23) | ERROR | Product search query built via string concatenation — SQL injection. **Fixed:** switched to Sequelize named `replacements` instead of string interpolation. |
| 3 | `remote-property-injection` | [routes/currentUser.ts:31](../juice-shop/routes/currentUser.ts#L31) | ERROR | Request-controlled `?fields=` query param assigned directly into a response object with no allowlist — could leak the password hash (`?fields=password`, the "Password Hash Leak" challenge) or supply an object-injection key like `__proto__`. **Fixed:** restricted to a fixed allowlist of non-sensitive fields (`id`, `email`, `lastLoginIp`, `profileImage`). This intentionally breaks the "Password Hash Leak" challenge. |
| 4 | `code-string-concat` / `eval-detected` | [routes/userProfile.ts:65](../juice-shop/routes/userProfile.ts#L65) | ERROR / WARNING | User profile "name" rendered via string concatenation into a template that gets evaluated — the classic Juice Shop stored-XSS-via-eval / SSTI challenge. Same line also flagged by ZAP's "Dangerous JS Functions" DAST finding. **Fixed:** `eval()` removed entirely; username is now only ever HTML-encoded literal text. This intentionally breaks the "Username XSS"/SSTI challenges (`usernameXssChallenge`, `sstiChallenge`) — see [RSN note](#known-limitation-rsn-refactoring-safety-net). |
| 5 | `eval-detected` | [routes/captcha.ts:22](../juice-shop/routes/captcha.ts#L22) | WARNING | `eval()` used to evaluate CAPTCHA answer. **Fixed:** replaced with a small precedence-aware `evaluateExpression()` helper — same three-term result, no code execution. (Operands here were always server-generated, not user input, so this was a hardening fix rather than a live exploit path.) |
| 6 | `hardcoded-hmac-key` (×2) | [lib/insecurity.ts:42](../juice-shop/lib/insecurity.ts#L42), [lib/insecurity.ts:150](../juice-shop/lib/insecurity.ts#L150) | WARNING | Hardcoded HMAC keys used for hashing — should be loaded from environment/secret store. **Fixed:** both now read from `process.env.HMAC_SECRET` / `process.env.JWT_PRIVATE_KEY` (line 150 reuses the private-key variable fixed in #7), with a dev-only fallback retained so the app still runs out of the box locally; the fallback must be overridden via env var in any real deployment. |
| 7 | `hardcoded-jwt-secret` | [lib/insecurity.ts:54](../juice-shop/lib/insecurity.ts#L54) | WARNING | JWT signing secret hardcoded in source (private key file is also committed under `encryptionkeys/`) — allows forging tokens. **Fixed:** `privateKey` now reads from `process.env.JWT_PRIVATE_KEY` first, falling back to the original literal only for local/demo convenience. Note: the matching public key at `encryptionkeys/jwt.pub` is still the static committed file, so if you set `JWT_PRIVATE_KEY` in production you must also replace `encryptionkeys/jwt.pub` with the corresponding public key or token verification will break. |
| 8 | `express-res-sendfile` (×4) | [routes/fileServer.ts:32](../juice-shop/routes/fileServer.ts#L32), [routes/keyServer.ts:14](../juice-shop/routes/keyServer.ts#L14), [routes/logfileServer.ts:14](../juice-shop/routes/logfileServer.ts#L14), [routes/quarantineServer.ts:14](../juice-shop/routes/quarantineServer.ts#L14) | WARNING | `res.sendFile()` with user-influenced path — path traversal risk if not strictly sanitized/allow-listed. Each route only blocked `/` in the filename, which doesn't stop backslash-based traversal on Windows or other encoding tricks. **Fixed:** added `resolveSafePath()` to [lib/utils.ts](../juice-shop/lib/utils.ts) — resolves the path and verifies it's still inside the intended base directory before any of these routes call `res.sendFile()`, closing traversal regardless of separator/encoding. |
| 9 | `path-join-resolve-traversal` | [lib/antiCheat.ts:196](../juice-shop/lib/antiCheat.ts#L196) | WARNING | Path built via `path.join`/`resolve` with untrusted input. **Reviewed, no fix needed (false positive):** `relativePath` here only ever comes from the hardcoded internal `challengeSourceFiles` map (see [antiCheat.ts:55](../juice-shop/lib/antiCheat.ts#L55)), never from request input — there's no reachable untrusted-input path to this sink. |
| 10 | `express-open-redirect` | [routes/redirect.ts:18](../juice-shop/routes/redirect.ts#L18) | WARNING | Redirect target taken from request without allow-list validation. The underlying check in `security.isRedirectAllowed()` used `url.includes(allowedUrl)` — passes for any URL that merely *contains* an allowlisted URL as a substring. **Fixed:** switched to exact match (`redirectAllowlist.has(url)`) in [lib/insecurity.ts](../juice-shop/lib/insecurity.ts). |
| 11 | `express-check-directory-listing` (×5) | [server.ts:268,288,292,296,300](../juice-shop/server.ts#L268) (pre-fix line numbers) | WARNING | `serve-index` directory browsing enabled on `/infrastructure`, `/ftp`, `/.well-known`, `/encryptionkeys`, `/support/logs` — full directory listings exposed (this *is* the "Directory Listing" and "Access Log Disclosure" challenges). **Fixed:** removed all `serveIndex()` mounts and the now-unused `serveIndexMiddleware` helper/`serve-index` import from `server.ts`; direct file access by exact filename (already hardened against path traversal, see #8) is preserved on all five paths. |
| 12 | `unknown-value-with-script-tag` | [routes/videoHandler.ts:71](../juice-shop/routes/videoHandler.ts#L71) | WARNING | Subtitle-file content (replaceable via the app's video-upload feature, so untrusted) spliced verbatim into a `<script>` tag — real stored XSS (the "Video XSS" challenge). **Fixed:** HTML-encode the content before splicing it in, which also neutralizes literal `</script>` breakout. |
| 13 | `template-explicit-unescape` | [views/promotionVideo.pug:75](../juice-shop/views/promotionVideo.pug#L75) | WARNING | Pug template explicitly disables auto-escaping (`!=`) for a value — XSS risk if that value is user-influenced. **Reviewed, no fix needed (false positive):** line 75 is the JS inequality operator (`if (splitted.length != 2)`) inside a static, hardcoded `script.` block with no Pug interpolation at all — Semgrep matched the `!=` token textually, not Pug's raw-output syntax. The real XSS risk in this file's rendering path is #12, already fixed. |
| 14 | `prototype-pollution-loop` | [frontend/src/hacking-instructor/helpers/helpers.ts:49](../juice-shop/frontend/src/hacking-instructor/helpers/helpers.ts#L49) | WARNING | Loop copying properties without an own-property guard — prototype pollution pattern. **Reviewed, no fix needed (false positive):** `options.replacement` is only ever a hardcoded 2-element array (e.g. `['juice-sh.op', 'application.domain']`) baked into this frontend's own tutorial step definitions (see `frontend/src/hacking-instructor/challenges/*.ts`) — never derived from user or network input. |
| 15 | `detect-non-literal-regexp` (×2) | [lib/codingChallenges.ts:76,78](../juice-shop/lib/codingChallenges.ts#L76) | WARNING | RegExp built from non-literal input — ReDoS risk if that input is attacker-controlled. **Reviewed, no fix needed (false positive):** `challengeKey` here comes exclusively from parsing `// vuln-code-snippet start <keys>` comments in this project's own source files at startup (see `getCodeChallengesFromFile`, [lib/codingChallenges.ts:50](../juice-shop/lib/codingChallenges.ts#L50)) — never from a request. |
| 16 | `unsafe-formatstring` | [server.ts](../juice-shop/server.ts) (`console.error('Error in timed startup function: ' + name, err)`) | INFO | Format string built with non-constant input. **Reviewed, no fix needed (false positive):** `name` is always a hardcoded literal at every call site (`collectDurationPromise('validatePreconditions', ...)` etc.) — never request-derived — and `err` is passed as a separate argument, not interpolated into the format string. |
| 17 | `detected-generic-secret` | [data/static/users.yml:151](../juice-shop/data/static/users.yml#L151) | ERROR | Secret-shaped string in static seed data. **Reviewed, no fix needed:** this is intentional demo/seed data (a fixture user record), not a live credential. |

### Infra / CI findings (out of scope for app remediation, listed for completeness)

- `github-actions-mutable-action-tag` ×7 — GitHub Actions pinned to mutable tags (e.g. `@v4`) instead of a commit SHA.
- `run-shell-injection` ×5, `gha-curl-pipe-shell` ×1 — CI workflow steps that interpolate untrusted input into shell commands, or pipe `curl` output to a shell.
- `aws-elb-access-logs-not-enabled` ×5, `aws-subnet-has-public-ip-address` ×5, `insecure-load-balancer-tls-version` ×5, `aws-cloudwatch-log-group-unencrypted` ×2 — Terraform configs (example/reference infra bundled in the repo, not deployed by this project).
- `npm-missing-minimum-release-age` ×2 — dependency-freshness policy findings, not vulnerabilities per se.
- `detected-jwt-token` ×3 (in `*.spec.ts` test files) — example JWTs used as test fixtures, not live secrets.
- `detect-replaceall-sanitization` ×2 (in `data/static/codefixes/*`) and the two `express-sequelize-injection` hits in `data/static/codefixes/*` — these are Juice Shop's own **bundled challenge solutions/exercises** (intentionally vulnerable/fixed code samples shown to players), not the app's live code path.

### Known limitations

**No local Node/npm/TypeScript toolchain.** This project only has Docker available (see [README.md](../README.md)) — there's no way to run `npm install`, `tsc`, `npm test`, or rebuild the Angular frontend locally to compile-check or test these fixes before the remediated re-scan. All source edits were made by careful manual review of each flagged line and its call sites rather than verified by a build. This mainly affects:
- **RSN (Refactoring Safety Net)** — several fixed lines (e.g. `login.ts:34`, `search.ts:23`) sit inside Juice Shop's own `// vuln-code-snippet` blocks, checked for consistency against `data/static/codefixes/*` via `npm run rsn`. Not run here.
- **Frontend bundle findings** (ZAP #5, #7) — left open since they live in a compiled `frontend/dist/` artifact this project can't rebuild.
- **Helmet API usage** — `helmet.crossOriginEmbedderPolicy()` / `helmet.crossOriginOpenerPolicy()` (added in helmet v4.6.0, which `package.json` pins) haven't been compiled/run to confirm against the exact installed version.

Fixing the intentional vulnerabilities is also expected to break their corresponding CTF challenges (e.g. "Login Admin", "Union SQL Injection", "Username XSS"/SSTI, "Password Hash Leak", "Directory Listing", "Access Log Disclosure") — out of scope for this security-remediation exercise, but worth knowing if you also care about Juice Shop's own challenge suite staying playable.

## Before / After Summary

Remediated app built from the fixed source via `docker build -t juice-shop-remediated ./juice-shop` (official Dockerfile) and run on port 3001 alongside the untouched baseline on port 3000, so both were scanned with identical tooling for a fair comparison. Spot-checked directly against the running app before scanning: SQL injection payload in login now returns a clean "Invalid email or password." instead of bypassing auth; CORS no longer reflects an arbitrary `Origin`; open-redirect payload now returns `406`; CSP/COEP/COOP/Permissions-Policy headers all present.

| Metric | Baseline | Remediated |
|---|---|---|
| ZAP FAIL | 0 | 0 |
| ZAP WARN | 8 | **5** |
| ZAP PASS | 59 | **62** |
| Semgrep ERROR | 18 | **15** |
| Semgrep WARNING | 45 | **35** |
| Semgrep total | 68 | **55** |

Full remediated reports: [zap-baseline-report.html](reports/remediated/zap-baseline-report.html) / [zap-baseline-report.json](reports/remediated/zap-baseline-report.json) / [semgrep-remediated.json](reports/remediated/semgrep-remediated.json).

**ZAP — resolved:** CSP Header Not Set, Cross-Domain Misconfiguration, Cross-Origin-Embedder/Opener-Policy Missing (now "Insufficient Site Isolation Against Spectre" — same rule 90004 — PASS), Deprecated Feature-Policy Header (now "Permissions Policy Header Not Set" — PASS). **Still open (unchanged, both flagged as out of scope earlier):** Dangerous JS Functions, Timestamp Disclosure. **New WARNs after remediation:** "CSP: Failure to Define Directive with No Fallback" (×12) — an expected side effect of adding a CSP at all: ours sets `default-src`/`script-src`/`style-src` etc. but not every directive ZAP checks for (e.g. `media-src`), a deliberate trade-off to avoid over-restricting a frontend we can't rebuild-and-test iteratively; and "Storable and Cacheable Content" (×6), a minor caching heuristic, not a fix regression.

**Semgrep — resolved (no longer flagged at all):** SQL injection in `login.ts`/`search.ts`, hardcoded HMAC/JWT secrets in `insecurity.ts`, both `eval()` usages (`userProfile.ts`, `captcha.ts`), directory listing (`server.ts`). **Resolved in behavior but still statically flagged** (Semgrep matches the syntactic shape — e.g. any `res.sendFile()`/`res.redirect()` call with a variable argument, or any assignment shaped like `obj[field] = ...` — not whether a guard around it actually neutralizes the risk, so these remain false-positive-after-fix): path traversal in the four file-serving routes (still calls `res.sendFile()`, now via the traversal-safe `resolveSafePath()`), open redirect in `redirect.ts` (still calls `res.redirect()`, now gated by exact-match allowlist), field-selection injection in `currentUser.ts` (still assigns by dynamic key, now allowlist-gated), and the video-subtitle XSS in `videoHandler.ts` (still splices next to a `<script>` tag, now HTML-encoded first). **Unchanged, already documented as out of scope or false positive:** the four `data/static/codefixes/*` SQLi fixtures, `promotionVideo.pug` false positive, `antiCheat.ts`/`helpers.ts`/`codingChallenges.ts` false positives (unreachable input), `server.ts` format-string false positive, `users.yml` seed-data secret.
