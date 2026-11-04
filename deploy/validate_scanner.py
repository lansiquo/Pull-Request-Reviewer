"""Real scanner compatibility checks; fixture source is scanned, never executed."""
import os
os.environ['PRSEC_LOAD_DOTENV'] = '0'
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import OFFLINE_RULESET
from analyzers.semgrep_runner import run_semgrep

SOURCE = '''import hashlib, os, pickle, random, subprocess, tarfile, tempfile, yaml
hashlib.md5(b"demo")  # nosemgrep
hashlib.sha1(b"demo")
yaml.load("example")
yaml.unsafe_load("example")
pickle.loads(b"example")
pickle.load(stream)
os.system(user_input)
os.popen(user_input)
subprocess.run(user_input, shell=True)
eval(user_input)
exec(user_input)
requests.get("https://example.invalid", verify=False)
random.random()
tempfile.mktemp()
with tarfile.open("example.tar") as archive:
    archive.extractall("target")
'''
EXPECTED = {'py-weak-md5','py-weak-sha1','py-unsafe-yaml-load','py-unsafe-yaml-unsafe-load',
    'py-insecure-deserialization-pickle-loads','py-insecure-deserialization-pickle-load',
    'py-os-system','py-os-popen','py-subprocess-shell-true','py-dangerous-eval','py-dangerous-exec',
    'py-requests-disable-verify','py-random-for-secrets','py-tempfile-mktemp','py-tarfile-extractall'}


def main():
    with tempfile.TemporaryDirectory(prefix='prsec_compatibility_') as temporary:
        root=Path(temporary)
        (root/'all_rules.py').write_text(SOURCE)
        (root/'clean.py').write_text('import hashlib\nhashlib.sha256(b"demo")\n')
        rules=root/'trusted.yml';rules.write_text(OFFLINE_RULESET)
        findings=run_semgrep(['all_rules.py'],str(root),config=str(rules))
        actual={f['rule_id'] for f in findings}
        assert actual == EXPECTED, f'Unexpected rule coverage: missing={EXPECTED-actual}, extra={actual-EXPECTED}'
        assert not run_semgrep(['clean.py'],str(root),config=str(rules))
        print('PASS: all 15 trusted rules; inline nosemgrep cannot suppress MD5; clean comparison passes.')


if __name__ == '__main__': main()
