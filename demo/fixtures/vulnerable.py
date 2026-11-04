# Deliberately insecure static-analysis fixture. Never execute this file.
import hashlib
import subprocess


def unsafe_digest(data):
    return hashlib.md5(data).hexdigest()


def unsafe_command(user_input):
    return subprocess.run(user_input, shell=True)
