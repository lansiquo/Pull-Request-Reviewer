import hashlib
import hmac
import json
from importlib import reload

from fastapi.testclient import TestClient

BODY = json.dumps({"zen": "hi"}).encode()


def _client(monkeypatch, secret=None, allow_unverified="0"):
    for var in ("GITHUB_WEBHOOK_SECRET", "GITHUB_WEBHOOK_SECRETS"):
        if secret is None:
            monkeypatch.delenv(var, raising=False)
        else:
            monkeypatch.setenv(var, secret)
    monkeypatch.setenv("ALLOW_UNVERIFIED_WEBHOOKS", allow_unverified)
    import app as appmod
    reload(appmod)
    return TestClient(appmod.app)


def _post(client, signature=None):
    headers = {"X-GitHub-Event": "ping", "X-GitHub-Delivery": "t-1", "Content-Type": "application/json"}
    if signature:
        headers["X-Hub-Signature-256"] = signature
    return client.post("/webhook", content=BODY, headers=headers).json()


def test_rejects_when_no_secret_configured(monkeypatch):
    client = _client(monkeypatch, secret=None)
    assert _post(client) == {"ok": False, "error": "Webhook secret not configured", "delivery": "t-1"}


def test_rejects_bad_signature(monkeypatch):
    client = _client(monkeypatch, secret="s3cret")
    assert _post(client, "sha256=" + "0" * 64)["error"] == "Invalid signature"


def test_accepts_valid_signature(monkeypatch):
    client = _client(monkeypatch, secret="s3cret")
    sig = "sha256=" + hmac.new(b"s3cret", BODY, hashlib.sha256).hexdigest()
    assert _post(client, sig) == {"ok": True, "pong": True}


def test_opt_out_allows_unsigned(monkeypatch):
    client = _client(monkeypatch, secret=None, allow_unverified="1")
    assert _post(client) == {"ok": True, "pong": True}
