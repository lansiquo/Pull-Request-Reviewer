# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A07 Identification and Authentication Failures: hardcoded admin password."""
ADMIN_PASSWORD = "Summer2026!"


def login(username, password):
    return username == "admin" and password == ADMIN_PASSWORD
