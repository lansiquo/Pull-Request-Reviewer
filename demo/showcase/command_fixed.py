# Trusted analysis sample. The demo never executes this command.
import re
import subprocess


def display_message(message):
    if not isinstance(message, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}', message):
        raise ValueError('Use 1-80 permitted characters, starting with a letter or digit')
    return subprocess.run(['/bin/echo', message], shell=False, check=True)
