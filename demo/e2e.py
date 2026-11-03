"""Offline end-to-end demo of the PR Reviewer.

Starts the real reviewer service and a fake GitHub API on localhost, then sends
a signed pull_request webhook for a PR that adds demo/sample_pr/vulnerable.py
(INTENTIONALLY VULNERABLE) and clean.py. Prints the comment and check run the
reviewer posts, then shows that a forged (unsigned) webhook is rejected.

Run: make demo   (or: python -m demo.e2e)
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import socket
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SECRET = "demo-secret"
GH_PORT, APP_PORT = 9010, 8010

# The reviewer reads its config at import time, so set it before importing.
os.environ.update({
    "GITHUB_API": f"http://127.0.0.1:{GH_PORT}",
    "EXPLICIT_INSTALLATION_TOKEN": "demo-token",
    "FORCE_EXPLICIT_TOKEN": "1",
    "GITHUB_WEBHOOK_SECRET": SECRET,
    "GITHUB_WEBHOOK_SECRETS": SECRET,
    "ALLOW_UNVERIFIED_WEBHOOKS": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LOGLEVEL": "WARNING",
    "NO_PROXY": "127.0.0.1,localhost",
    "no_proxy": "127.0.0.1,localhost",
})

import requests  # noqa: E402
import uvicorn  # noqa: E402

calls: list = []
done = threading.Event()


def _pr_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for f in sorted((ROOT / "sample_pr").glob("*.py")):
            tf.add(f, arcname=f"demo-repo-abc1234/{f.name}")
    return buf.getvalue()


TARBALL = _pr_tarball()
PR_FILES = [{"filename": f.name, "status": "added"} for f in sorted((ROOT / "sample_pr").glob("*.py"))]


class FakeGitHub(BaseHTTPRequestHandler):
    """Answers the few GitHub API calls the reviewer makes and records what it posts."""

    def log_message(self, *args):
        pass

    def _send(self, code, obj=None, raw=None, ctype="application/json"):
        body = raw if raw is not None else json.dumps(obj if obj is not None else {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if "/tarball/" in self.path:
            return self._send(200, raw=TARBALL, ctype="application/gzip")
        if "/pulls/" in self.path and self.path.split("?")[0].endswith("/files"):
            first_page = "page=1" in self.path or "page=" not in self.path
            return self._send(200, PR_FILES if first_page else [])
        self._send(404, {"message": f"not mocked: {self.path}"})

    def do_POST(self):
        data = self._json()
        if self.path.endswith("/comments"):
            calls.append(("comment", data))
            return self._send(201, {"id": 1, "html_url": "http://fake-github/pr/1#comment-1"})
        if self.path.endswith("/check-runs"):
            calls.append(("check_created", data))
            return self._send(201, {"id": 42, "html_url": "http://fake-github/checks/42"})
        self._send(404, {})

    def do_PATCH(self):
        data = self._json()
        calls.append(("check_updated", data))
        if data.get("conclusion"):
            done.set()
        self._send(200, {"id": 42})


def _wait_for_port(port: int, timeout: float = 20) -> None:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise RuntimeError(f"nothing listening on port {port}")


def _send_webhook(body: bytes, signature: str, delivery: str) -> dict:
    return requests.post(f"http://127.0.0.1:{APP_PORT}/webhook", data=body, timeout=30, headers={
        "X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery,
        "Content-Type": "application/json", "X-Hub-Signature-256": signature}).json()


def main() -> None:
    from app import app as reviewer

    threading.Thread(target=HTTPServer(("127.0.0.1", GH_PORT), FakeGitHub).serve_forever, daemon=True).start()
    server = uvicorn.Server(uvicorn.Config(reviewer, host="127.0.0.1", port=APP_PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    _wait_for_port(GH_PORT)
    _wait_for_port(APP_PORT)

    body = json.dumps({
        "action": "opened", "number": 1, "installation": {"id": 0},
        "pull_request": {
            "head": {"sha": "abc1234def5678", "repo": {"name": "demo-repo", "owner": {"login": "demo"}}},
            "base": {"sha": "0000000", "repo": {"name": "demo-repo", "owner": {"login": "demo"}}},
        },
    }).encode()
    good_sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()

    print("\n1) Signed webhook: PR #1 adds vulnerable.py and clean.py")
    print("   reviewer replied:", _send_webhook(body, good_sig, "demo-signed"))
    if not done.wait(120):
        print("   timed out waiting for the check to finish")

    for kind, data in calls:
        if kind == "comment":
            print("\n   PR comment:", data.get("body"))
        elif kind == "check_created":
            print(f"   Check '{data.get('name')}' created: {data.get('status')}")
        elif data.get("conclusion"):
            out = data.get("output", {})
            print(f"\n   Check finished: {data['conclusion'].upper()}")
            print("   " + (out.get("summary") or "").replace("\n", "\n   "))
            for a in out.get("annotations", []):
                print(f"   ✖ {a['path']}:{a['start_line']}  {a['message']}")

    print("\n2) Forged webhook with a bad signature")
    print("   reviewer replied:", _send_webhook(body, "sha256=" + "0" * 64, "demo-forged"))
    server.should_exit = True


if __name__ == "__main__":
    main()
