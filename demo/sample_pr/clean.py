"""Safe version: the reviewer should not flag anything here."""
import hashlib
import subprocess

import yaml


def ping(host):
    subprocess.run(["ping", "-c", "1", host], check=True)


def load(text):
    return yaml.safe_load(text)


def digest(data):
    return hashlib.sha256(data).hexdigest()
