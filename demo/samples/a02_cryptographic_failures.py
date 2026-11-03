# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A02 Cryptographic Failures: weak password hashing and disabled TLS checks."""
import hashlib

import requests


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def fingerprint(data):
    return hashlib.sha1(data).hexdigest()


def fetch_rates():
    return requests.get("https://rates.example.com", verify=False).json()
