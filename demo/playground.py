"""Local playground for the PR Reviewer.

Paste code or pick an OWASP Top 10 sample, and see what the reviewer flags.
The samples in demo/samples are INTENTIONALLY VULNERABLE. They are only scanned,
never imported or run.

Run:  make playground   (or: python -m demo.playground)
Open: http://127.0.0.1:8765
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from analyzers.semgrep_runner import run_semgrep, to_github_annotations  # noqa: E402
from app import OFFLINE_RULESET  # noqa: E402

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
SAMPLES = ROOT / "samples"
MAX_CODE_BYTES = 50_000

# What each sample shows. "caught" means the reviewer's rules should flag it;
# "missed" means pattern rules can't see it, which is part of the lesson.
SAMPLE_INFO = {
    "a01_broken_access_control.py": ("A01", "Broken Access Control", "missed",
        "Ownership checks are business logic. Needs code review or authorization tests."),
    "a02_cryptographic_failures.py": ("A02", "Cryptographic Failures", "caught",
        "Weak hashes and disabled TLS verification are clear code patterns."),
    "a03_injection.py": ("A03", "Injection", "caught",
        "Shell and eval injection are caught. The f-string SQL query is missed: that needs taint rules."),
    "a04_insecure_design.py": ("A04", "Insecure Design", "partial",
        "The weak random code is flagged as a warning. The missing rate limit is a design gap no rule sees."),
    "a05_security_misconfiguration.py": ("A05", "Security Misconfiguration", "extended",
        "Built-in rules miss it. Turn on the extended rules to catch Flask debug mode."),
    "a06_vulnerable_components.py": ("A06", "Vulnerable and Outdated Components", "missed",
        "This is SCA territory: the risk is in dependency versions, not this code."),
    "a07_auth_failures.py": ("A07", "Identification and Authentication Failures", "missed",
        "Hardcoded secrets need a secret scanner or extended rules."),
    "a08_integrity_failures.py": ("A08", "Software and Data Integrity Failures", "caught",
        "pickle, yaml.load and tarfile.extractall are all flagged."),
    "a09_logging_failures.py": ("A09", "Security Logging and Monitoring Failures", "missed",
        "Silent failures are hard to pattern-match. Needs review."),
    "a10_ssrf.py": ("A10", "Server-Side Request Forgery", "missed",
        "Needs data-flow (taint) analysis to know the URL comes from a user."),
}

app = FastAPI(title="PR Reviewer Playground", docs_url=None, redoc_url=None)


class ScanRequest(BaseModel):
    code: str
    extended: bool = False


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "playground.html").read_text(encoding="utf-8")


@app.get("/api/samples")
def samples() -> list:
    out = []
    for name, (code, title, expect, note) in SAMPLE_INFO.items():
        out.append({"file": name, "code": code, "title": title, "expect": expect, "note": note,
                    "source": (SAMPLES / name).read_text(encoding="utf-8")})
    return out


@app.post("/api/scan")
def scan(req: ScanRequest):
    if len(req.code.encode("utf-8")) > MAX_CODE_BYTES:
        return JSONResponse({"error": "Code is too large (50 KB max)."}, status_code=413)
    with tempfile.TemporaryDirectory(prefix="prsec_play_") as td:
        tdp = Path(td)
        (tdp / "snippet.py").write_text(req.code, encoding="utf-8")
        rules = tdp / ".semgrep.yaml"
        rules.write_text(OFFLINE_RULESET, encoding="utf-8")
        configs = [str(rules)]
        if req.extended:
            configs.append(str(REPO / "rules"))
        findings = run_semgrep(paths=["snippet.py"], repo_root=td, config=",".join(configs), timeout_s=60)
        annotations = to_github_annotations(findings)
    # Same verdict the GitHub check would give
    conclusion = "failure" if any(a.get("annotation_level") == "failure" for a in annotations) else "success"
    # Rule files overlap, so merge findings on the same line into one entry.
    rank = {"failure": 2, "warning": 1, "notice": 0}
    by_line: dict = {}
    for a in annotations:
        line = a.get("start_line") or 0
        entry = by_line.setdefault(line, {"line": line, "level": "notice", "messages": []})
        level = a.get("annotation_level") or "notice"
        if rank.get(level, 0) > rank.get(entry["level"], 0):
            entry["level"] = level
        msg = (a.get("message") or "").strip()
        if msg and msg not in entry["messages"]:
            entry["messages"].append(msg)
    return {"conclusion": conclusion, "findings": [by_line[k] for k in sorted(by_line)]}


if __name__ == "__main__":
    print("PR Reviewer playground: http://127.0.0.1:8765  (samples are intentionally vulnerable)")
    # Localhost only: this is a learning tool, not a service.
    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PLAYGROUND_PORT", "8765")), log_level="warning")
