# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A08 Software and Data Integrity Failures: unsafe deserialization and archive extraction."""
import pickle
import tarfile

import yaml


def load_session(blob):
    return pickle.loads(blob)


def load_settings(text):
    return yaml.load(text)


def unpack(path):
    with tarfile.open(path) as tf:
        tf.extractall("/srv/uploads")
