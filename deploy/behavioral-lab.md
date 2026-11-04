# Controlled behavioral lab

The six previously manual-only examples now execute their actual authored fixture functions against synthetic adapters. There is no inferred pass from a fixture name or string match. `demo/behavior_worker.py` records each security assertion's measured Boolean result, safe evidence and elapsed time. `demo_behavior.py` enforces the child-process boundary. The production scanner/rules and GitHub integration are unchanged.

| Category | Actual security assertions |
|---|---|
| A01 | Owner can read; another user is denied the invoice. |
| A03 | An approved synthetic artifact builds; an unapproved manifest and hash-tampered artifact each prevent release. No artifact executes or dependency installs. |
| A06 | A second redemption is denied; two concurrent requests issue credit exactly once using a transactional in-memory adapter with uniqueness and rollback. |
| A07 | The pre-login identifier becomes invalid; the new authenticated identifier is distinct. Synthetic identifiers are not printed. |
| A09 | Both requests remain denied; two structured events contain only allowed fields; the second event triggers one in-memory test alert. No alert is sent externally. |
| A10 | A healthy policy allow works; a policy timeout denies access. |

All six vulnerable variants fail at least one assertion, and all six fixed variants pass every assertion. Exit code zero means the harness completed and produced valid evidence, **not** that the security assertions passed. An exception, malformed evidence, changed fixture hash, timeout or output overflow yields an incomplete/error result and never green.

## Execution boundary

- Only six server-owned scenario names and two variant names are accepted. No source, path, repository, command or URL supplied by a client is executed.
- Each fixture must match `demo/behavior_hashes.json` before it is compiled/executed. Editing an example requires deliberate review and repinning; unreviewed edits fail closed.
- Each run uses a fresh temporary working directory, isolated Python mode (`-I`) and a minimal environment. Application keys, tokens, proxy settings, dotenv and Python search-path overrides are not inherited.
- The parent enforces a 5-second wall timeout and 64-KiB output ceiling. The child sets a 2-second CPU limit, 64-KiB file-size limit and 64-file-descriptor limit.
- A Python audit hook denies socket operations, child processes, shell execution, ctypes and access to files outside the temporary directory during fixture execution. Guard checks run before fixture execution.
- These controls are defense in depth for **trusted authored fixtures**, not a secure Python sandbox for hostile code. The worker is still a host process; no OS-container isolation claim is made. Never use this harness for PR code, uploads or arbitrary snippets.

## Interpretation

The adapters are controlled implementations, not mocks returning a desired verdict: invoice lookups, digest comparisons, transaction/uniqueness state, session mutation, structured records and threshold counts all change in response to the executed fixture. Nevertheless, passing them does not validate a real database's transactions, real package provenance/advisories, an identity provider, log delivery/retention or production error handling. The UI preserves those scope limits.

The behavioral stage is separate from Semgrep: the inapplicable stage says Not run. Both engines return real outcomes for the selected scenario/version; changing selection resets results and history retains its original fixture/evidence. Red and green code labels remain illustrative source guidance; the assertion list is the runtime evidence.

## Verified

- Full `make check`: **165 passed**, followed by expected real vulnerable/clean CLI scans.
- All twelve behavioral variant outcomes executed through API tests and the live GUI.
- Browser regression: all ten scenarios × both variants × desktop/mobile; exact status/engine, assertion evidence, visible source/diffs, red/green labels, annotations, same-run selection, history/reset, errors/retry, keyboard and inert HTML rendering.
- Negative tests cover unknown input, stripped secret-sentinel environment, child timeout, output overflow, fixture-hash mismatch and sanitized API errors.
- A metamorphic test places the fixed timeout code in a repinned *vulnerable-named* test fixture and observes success, proving the verdict follows executed behavior rather than the variant label.

Run `.venv/bin/python demo_web.py` and open http://127.0.0.1:8765. Stop with Ctrl+C. No public hosting, GitHub writes or production configuration changes are needed.
