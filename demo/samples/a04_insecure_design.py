# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A04 Insecure Design: password reset with no rate limit and a guessable 4-digit code."""
import random


def send_reset_code(user):
    user.reset_code = random.randint(1000, 9999)


def check_reset_code(user, code):
    return user.reset_code == int(code)  # unlimited attempts
