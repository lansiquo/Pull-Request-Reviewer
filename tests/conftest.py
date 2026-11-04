"""Tests never load local credentials or permit outbound HTTP."""
import os
import pytest
os.environ["PRSEC_LOAD_DOTENV"] = "0"
os.environ["GITHUB_WEBHOOK_SECRET"] = "testsecret"
os.environ["GITHUB_WEBHOOK_SECRETS"] = "testsecret"

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import requests
    def blocked(*args, **kwargs):
        raise AssertionError("Outbound HTTP is forbidden in tests")
    monkeypatch.setattr(requests.sessions.Session, "request", blocked)
