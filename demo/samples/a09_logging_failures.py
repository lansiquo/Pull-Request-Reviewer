# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A09 Security Logging and Monitoring Failures: failed logins are silently ignored."""


def login(user, password, check):
    try:
        return check(user, password)
    except Exception:
        pass  # no log, no alert, no lockout
    return False
