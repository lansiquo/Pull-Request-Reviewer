# sast-triage

A GitHub App webhook service that reviews changed Python files with Semgrep and reports findings as GitHub Check Run annotations. Designed as a local portfolio demonstration of a security automation pipeline. It is the SAST companion to [sca-triage](https://github.com/lansiquo/lansiquo-sca-remediation-lab), which ranks npm dependency vulnerabilities by whether your code actually loads them.

## Status: in development

**Works today:** signed webhooks, Semgrep scans of the changed Python files at the pull request's head commit using service-owned rules, fail-closed limits, an offline demo and regression suite (`make check`), and triage of every finding into GitHub Check Run annotations:

1. **New vs pre-existing.** The pull request's diff marks findings on added or changed lines as new. Findings elsewhere in a touched file are labelled pre-existing instead of being reported as if the pull request caused them.
2. **P1/P2/P3 priority, like sca-triage.** Semgrep severity (and the rule's own confidence or likelihood, where it has one) is combined with whether the file is runtime or test code. Each annotation shows its priority, and they are sorted by it.
3. **Gate only on what matters.** The Check Run fails only on new P1 findings.

**Not built yet: deployment.** The service runs locally. A durable deployment mode is prepared but has not been deployed; see [deploy/README.md](deploy/README.md).

## How findings are triaged

| | Meaning | On the Check Run |
|---|---|---|
| **P1** | High or critical severity in runtime code | Fails the check when new (red annotation) |
| **P2** | High or critical in test code, or medium in runtime code | Warning when new |
| **P3** | Everything else | Notice |

- **New** means the finding covers at least one line the pull request added or changed, read from GitHub's diff for that file. **Pre-existing** findings are still annotated, as notices, but never fail the check.
- If GitHub sends no diff for a file (it leaves out very large ones) or the diff can't be read, every finding in that file counts as new. A file that was only renamed counts as unchanged.
- **Test code** follows pytest and Django naming: a `test` or `tests` folder, `test_*.py`, `*_test.py`, `tests.py` or `conftest.py`.
- A rule whose metadata rates its own `confidence` or `likelihood` as `LOW` drops one level (P1 to P2, P2 to P3). The bundled rules don't set these yet.
- **Limit:** pre-existing means the flagged lines weren't touched, not that the pull request is unrelated. A change elsewhere, such as a new import, can make an untouched line match, and that finding is still labelled pre-existing.

The Check Run title counts the new P1 findings, and the summary shows the gate result and a priority × new/pre-existing table. The rules live in `analyzers/triage.py`.

## Five-minute local demonstration

Use Python 3.11–3.13. No GitHub account, token, tunnel, or webhook secret is needed for the demo.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make check
```

`make test` runs the offline regression suite with HTTP blocked. `make demo` runs real Semgrep against two local source fixtures, never executes them, and prints the triage and the resulting GitHub annotation JSON. For `vulnerable.py` it simulates a pull request that adds the shell call. Expect **FAILURE**, because shell execution is `[P1, new]`; the MD5 call that was already there is `[P1, pre-existing]` and doesn't fail the check. Expect **SUCCESS** with zero findings for `clean.py`. Scanner/configuration errors cause a nonzero exit.

For an existing setup, run `make check` directly. Make uses `.venv/bin/python` when present, otherwise `python3`; `PY` can override this. The scanner searches beside that Python and then along PATH, skipping scripts whose shebang points to a missing interpreter (a common moved-virtualenv issue). An explicit `SEMGREP_BIN` is honored strictly and fails if unusable. No global tools or environment packages are changed.

## What to present

1. Run `make demo` to show insecure code, rule IDs, CWE context, line numbers, priority and new/pre-existing labels, and a clean comparison.
2. Run `make test` to show regression coverage for authentication, hostile archives, scan isolation, and failure reporting.
3. Walk through the flow: signed webhook → validated immutable commit → bounded archive → selected Python source → trusted rules → triage against the pull request's diff → Check Run annotations.
4. Explain the trust boundaries and deployment limitations in [SECURITY.md](SECURITY.md).

## Webhook service setup

Copy `.env.example` to `.env` and configure a strong webhook secret plus GitHub App ID and PEM path. Keep the PEM outside the repository. Run `make serve`; `/health` reports liveness and `/docs` exposes the API schema. The listener binds to loopback by default.

For a separately approved GitHub demonstration, configure the App for pull request events with Contents read, Pull requests read, and Checks write permissions. Exposing the server via Smee or another tunnel and installing the App are separate operator actions. This repository does not create grants, install Apps, change branch protections, or publish itself. A real authenticated PR webhook **does create/update remote Check Runs**, so use a designated test repository. Receipt comments are no longer posted.

Accepted PR actions: opened, reopened, synchronize, edited, ready_for_review. HMAC-SHA256 is mandatory; `GITHUB_WEBHOOK_SECRETS` supports comma-separated rotation values. Missing secrets return 503, bad signatures 401, malformed payloads 400, oversized bodies 413, busy scanners 503, and GitHub setup failures 502. Accepted requests return 200; scan results arrive through Check Runs.

Scans use service-owned embedded Python rules only. They inspect whole changed files at PR HEAD, not just added lines; findings on lines the pull request didn't change are labelled pre-existing, not dropped. PR-provided rules and ignore files are not used. Deleted-only or unsupported-language changes receive a neutral result. Scanner errors and partial scan errors produce failure, never success. Findings are sorted P1 first, capped at 200 annotations and uploaded in batches of 50.

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
