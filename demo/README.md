# PR Reviewer demos

> [!WARNING]
> **Intentionally vulnerable code.** Everything in `samples/` and `sample_pr/` is deliberately
> insecure and exists only to be scanned. Never import, run, or deploy these files. The
> playground binds to `127.0.0.1` only; don't expose it to a network.

Both demos run fully offline and don't need a GitHub App or network access.

## Playground: `make playground`

Opens a web UI at <http://127.0.0.1:8765>.

- Pick one of the ten OWASP Top 10 (2021) samples, or choose **Write your own** and paste Python.
- **Scan** runs the same embedded ruleset the GitHub check uses and shows the verdict, with
  findings inline on the affected lines.
- **Extended rules** adds the broader rule packs in [`../rules/`](../rules).
- Code is written to a temporary directory, scanned and deleted. It is never executed.

What each sample shows:

| Sample | Result | Why |
|---|---|---|
| A01 Broken Access Control | missed | Ownership checks are business logic |
| A02 Cryptographic Failures | caught | MD5/SHA-1 and `verify=False` |
| A03 Injection | caught | `os.system`, `shell=True`, `eval` (the f-string SQL query is missed) |
| A04 Insecure Design | partly caught | Weak `random` is a warning; the missing rate limit isn't visible |
| A05 Security Misconfiguration | extended rules | Flask `debug=True` |
| A06 Vulnerable Components | missed | A dependency problem; needs SCA, not code rules |
| A07 Auth Failures | missed | Hardcoded secrets need a secret scanner |
| A08 Integrity Failures | caught | `pickle.loads`, `yaml.load`, `tarfile.extractall` |
| A09 Logging Failures | missed | Silent failures are hard to pattern-match |
| A10 SSRF | missed | Needs data-flow (taint) analysis |

The misses are deliberate: they show where pattern-based scanning stops and code review,
SCA or tests have to take over.

## End-to-end demo: `make demo`

Runs the real reviewer service and a fake GitHub API on localhost, then:

1. Sends a **signed** `pull_request` webhook for a PR that adds `sample_pr/vulnerable.py` and
   `sample_pr/clean.py`.
2. Prints the PR comment and the **failed** check run the reviewer posts, with one annotation
   per finding. `clean.py` has none.
3. Sends a **forged** webhook with a bad signature and shows it being rejected.

These files are listed in `../.semgrepignore`, so this repository's own PR checks don't flag them.
