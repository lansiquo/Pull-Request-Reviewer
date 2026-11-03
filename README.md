# PR Security Reviewer

A GitHub App that reviews pull requests for security issues. When a PR opens or updates, the
FastAPI service scans the changed Python files with Semgrep and reports a pass/fail
**Checks API** result with an inline annotation on each finding.

> [!WARNING]
> **This repository contains intentionally vulnerable code.** The files in
> [`demo/samples/`](demo/samples) and [`demo/sample_pr/`](demo/sample_pr) are deliberately
> insecure examples (command injection, unsafe deserialization, weak crypto and more) used to
> show what the reviewer catches. They are scanned, never executed. Do not import, run, or
> deploy them, and keep the playground on localhost.

## Try it locally (no GitHub App needed)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make playground   # web UI at http://127.0.0.1:8765
make demo         # end-to-end run in the terminal
```

- **Playground:** pick an OWASP Top 10 (2021) sample or paste your own Python, then scan it
  with the same rules the GitHub check uses. Each sample says whether the reviewer catches it,
  partly catches it, or misses it, because some categories (access control, insecure design,
  SSRF) need code review or data-flow analysis rather than pattern rules.
- **End-to-end demo:** starts the real reviewer and a fake GitHub API, sends a signed
  `pull_request` webhook for a PR that adds vulnerable code, prints the comment and failed check
  the reviewer posts, then shows a forged webhook being rejected.

See [`demo/README.md`](demo/README.md) for details.

## Run it against GitHub

1. Create a GitHub App with **Checks: read & write**, **Pull requests: read**, **Contents: read**,
   and subscribe it to **Pull request** events.
2. Copy `.env.example` to `.env` and fill in the app ID, private key and webhook secret.
3. Start the service: `uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}`
4. Expose it (for example `ngrok http 8000`) and set the App's webhook URL to `https://<host>/webhook`.
5. Install the App on a repo and open a PR.

For Docker and Proxmox deployment, see [DEPLOY.md](DEPLOY.md).

## How it works

- **Signed webhooks only.** Requests must carry a valid `X-Hub-Signature-256` for the
  configured secret. With no secret configured, every webhook is rejected unless you
  explicitly set `ALLOW_UNVERIFIED_WEBHOOKS=1` for local testing.
- **Deterministic scans.** An embedded offline ruleset runs on every PR (no registry fetch),
  plus the scanned repo's own `.semgrep.yaml` if it has one.
- **Bounded runtime.** Per-scan timeouts, a pipeline deadline and a watchdog make sure the
  check always completes instead of hanging.
- **No code is stored.** The PR snapshot is extracted to a temporary directory with path
  checks and deleted after the scan.

## Development

```bash
make test   # pytest
make scan   # Semgrep scan of this repo's changes against rules/
```
