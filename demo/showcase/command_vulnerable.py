# Trusted analysis sample. The demo never executes this command.
import subprocess


def display_message(message):
    return subprocess.run('echo ' + message, shell=True)
