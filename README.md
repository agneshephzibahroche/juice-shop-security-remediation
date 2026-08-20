# Vulnerable-App-to-Secure-App Refactor

A hands-on application security project: take a deliberately vulnerable app ([OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)), scan it with SAST and DAST tools, document what's found, fix it in the source, then re-scan to prove the fixes worked.

**Target:** OWASP Juice Shop v20.2.0
**SAST:** [Semgrep](https://semgrep.dev/) (`--config auto`)
**DAST:** [OWASP ZAP](https://www.zaproxy.org/) (baseline scan)

## Results at a glance

| | Baseline | Remediated |
|---|---|---|
| ZAP — Fail / Warn / Pass | 0 / 8 / 59 | _pending_ |
| Semgrep — Error / Warning / total | 18 / 45 / 68 | _pending_ |

Full write-up with evidence and fixes: [docs/vulnerabilities.md](docs/vulnerabilities.md)

## Repo structure

```
juice-shop/                  Juice Shop source (v20.2.0), vendored so fixes are committed here directly
docs/vulnerabilities.md      Findings log — each vuln, evidence, severity, fix applied
docs/reports/baseline/       Raw SAST + DAST output against the unmodified app
docs/reports/remediated/     Same scans re-run after fixes, for before/after comparison
```

## Methodology

1. **Baseline scans** — Semgrep against `juice-shop/` source, OWASP ZAP against a running instance of the unmodified app. Raw reports saved to `docs/reports/baseline/`.
2. **Triage** — review findings, drop noise/false positives, prioritize by severity and exploitability.
3. **Remediate** — fix vulnerabilities directly in `juice-shop/` source, one commit per fix (or logical group).
4. **Re-scan** — same Semgrep + ZAP scans against the fixed app, saved to `docs/reports/remediated/`.
5. **Compare** — before/after summary in `docs/vulnerabilities.md`.

## Reproducing this locally

Everything runs via Docker — no local Node/Java/Python install needed.

**1. Run the vulnerable app:**

```bash
docker run -d --name juice-shop-target -p 3000:3000 bkimminich/juice-shop:v20.2.0
```

App is then live at `http://localhost:3000`.

**2. Run the ZAP baseline scan against it:**

```bash
docker run --rm -v "$(pwd)/docs/reports/baseline:/zap/wrk:rw" -t zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 \
  -r zap-baseline-report.html -J zap-baseline-report.json
```

> On Windows with Git Bash, prefix with `MSYS_NO_PATHCONV=1` — otherwise Git Bash rewrites the container-side `/zap/wrk` path and the volume mount silently fails.

**3. Run the Semgrep scan against the source:**

```bash
docker run --rm -v "$(pwd):/src" semgrep/semgrep semgrep --config auto \
  /src/juice-shop --json --output /src/docs/reports/baseline/semgrep-baseline.json
```

(Same `MSYS_NO_PATHCONV=1` note applies on Windows Git Bash.)

## Status

Work in progress on branch `security-remediation`. Local only — not pushed to any remote yet.

## License

Juice Shop itself is MIT-licensed; see [`juice-shop/LICENSE`](juice-shop/LICENSE). This project's own documentation and fixes follow the same license unless noted otherwise.
