# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A10 Server-Side Request Forgery: the server fetches any URL the user supplies."""
import requests


def preview(url):
    return requests.get(url, timeout=5).text
