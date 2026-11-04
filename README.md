# PR Security Reviewer

A GitHub App webhook service that reviews changed Python files with Semgrep and reports findings as GitHub Check Run annotations. Designed as a local portfolio demonstration of a security automation pipeline.

## Public interactive demo

**[Try the interactive demo](https://dotrobin.dev/demos/pr.html)** — explore curated OWASP Top 10:2025 examples, compare proposed fixes, and read what each check can and cannot establish. No setup is required.

This standalone, static portfolio walkthrough is separate from the main application. It does not run Python, Semgrep, behavioral tests, or GitHub requests, and it does not scan uploaded code. For real scans against bundled trusted fixtures, use the local demonstrations below.

## Five-minute local demonstration

Use Python 3.11–3.13. No GitHub account, token, tunnel, or webhook secret is needed for the demo.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make check
```

`make test` runs the offline regression suite with HTTP blocked. `make demo` runs real Semgrep against two local source fixtures, never executes them, and prints the resulting GitHub annotation JSON. Expect **FAILURE** with two high-severity findings (MD5 and shell execution) for `vulnerable.py`, and **SUCCESS** with zero findings for `clean.py`. Scanner/configuration errors cause a nonzero exit.

For an existing setup, run `make check` directly. Make uses `.venv/bin/python` when present, otherwise `python3`; `PY` can override this. The scanner searches beside that Python and then along PATH, skipping scripts whose shebang points to a missing interpreter (a common moved-virtualenv issue). An explicit `SEMGREP_BIN` is honored strictly and fails if unusable. No global tools or environment packages are changed.

## What to present

1. Run `make demo` to show insecure code, rule IDs, CWE context, line numbers, and a clean comparison.
2. Run `make test` to show regression coverage for authentication, hostile archives, scan isolation, and failure reporting.
3. Walk through the flow: signed webhook → validated immutable commit → bounded archive → selected Python source → trusted rules → Check Run annotations.
4. Explain the trust boundaries and deployment limitations in [SECURITY.md](SECURITY.md).

## Webhook service setup

Copy `.env.example` to `.env` and configure a strong webhook secret plus GitHub App ID and PEM path. Keep the PEM outside the repository. Run `make serve`; `/health` reports liveness and `/docs` exposes the API schema. The listener binds to loopback by default.

For a separately approved GitHub demonstration, configure the App for pull request events with Contents read, Pull requests read, and Checks write permissions. Exposing the server via Smee or another tunnel and installing the App are separate operator actions. This repository does not create grants, install Apps, change branch protections, or publish itself. A real authenticated PR webhook **does create/update remote Check Runs**, so use a designated test repository. Receipt comments are no longer posted.

Accepted PR actions: opened, reopened, synchronize, edited, ready_for_review. HMAC-SHA256 is mandatory; `GITHUB_WEBHOOK_SECRETS` supports comma-separated rotation values. Missing secrets return 503, bad signatures 401, malformed payloads 400, oversized bodies 413, busy scanners 503, and GitHub setup failures 502. Accepted requests return 200; scan results arrive through Check Runs.

Scans use service-owned embedded Python rules only. They inspect whole changed files at PR HEAD, not just added lines. PR-provided rules and ignore files are not used. Deleted-only or unsupported-language changes receive a neutral result. Scanner errors and partial scan errors produce failure, never success. Findings are capped at 200 annotations and uploaded in batches of 50.

## Prepared deployment mode

See [deploy/README.md](deploy/README.md) for the verified existing GitHub App, repository scope, durable queue, isolated scanner design, dependency findings, and remaining approval/testing gates. This mode has not been deployed. The default local demo remains available.

## Scope and limits

- Small Python-focused ruleset; not a comprehensive security audit or proof that code is safe.
- No dependency, secret, JavaScript, or infrastructure scanning. Pattern matches can require human triage.
- Up to 1 MiB webhook body, 25 MiB compressed archive, 100 MiB extracted data, 10,000 members, and 3,000 changed-file entries. Large PRs fail closed.
- Default local mode has two concurrent in-memory jobs and is not a deployment service. The prepared durable mode uses SQLite and a separately supervised worker; its exact guarantees and limits are documented in the deployment guide.
- Semgrep has a subprocess timeout, but the service has no hard end-to-end job deadline. HTTP timeouts are per request, not total download deadlines.
- Scanner credentials are removed from its environment and only selected source files are staged. This is **not an OS sandbox**; use a separate unprivileged worker with CPU/memory/disk limits and denied network egress before scanning public hostile repositories at scale.
- The original local demo environment is preserved and has known dependency findings. Use the separately audited service lock for deployment preparation. No live GitHub or Docker deployment is claimed by the offline demo.

Historical branch-protection examples under `.github/branch-protection/` are retained as reference, not automatically applied. See [SECURITY.md](SECURITY.md) for threat boundaries.

## Local interactive showcase

Run `.venv/bin/python demo_web.py` and open http://127.0.0.1:8765. Select the proposed fixture, inspect live findings, compare the remediation, and rescan. Stop with Ctrl+C. PR presentation is simulated; scans are real and limited to bundled trusted fixtures. See [demo instructions and limitations](deploy/local-showcase.md).
