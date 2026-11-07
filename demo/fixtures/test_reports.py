# Deliberately insecure static-analysis test fixture. Never execute this file.
import pickle
import tempfile


def load_snapshot(blob):
    return pickle.loads(blob)


def scratch_path():
    return tempfile.mktemp()
