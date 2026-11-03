# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A03 Injection: user input reaches a shell, the interpreter, and a SQL string."""
import os
import subprocess


def ping(host):
    os.system("ping -c 1 " + host)
    subprocess.run(f"nslookup {host}", shell=True)


def calc(expr):
    return eval(expr)


def find_user(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
