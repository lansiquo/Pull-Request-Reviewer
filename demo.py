"""Offline portfolio demo: real scanner, local fixtures, no GitHub calls."""
import os
os.environ['PRSEC_LOAD_DOTENV'] = '0'
import json
import tempfile
from pathlib import Path
from app import OFFLINE_RULESET
from analyzers.semgrep_runner import run_semgrep, summarize_findings, to_github_annotations
from analyzers.triage import added_lines, gate, triage

# A simulated pull request against vulnerable.py: it adds `import subprocess`
# and unsafe_command(). The md5 call was already there, so it is pre-existing.
PULL_REQUEST_DIFF = """@@ -1,6 +1,11 @@
 # Deliberately insecure static-analysis fixture. Never execute this file.
 import hashlib
+import subprocess


 def unsafe_digest(data):
     return hashlib.md5(data).hexdigest()
+
+
+def unsafe_command(user_input):
+    return subprocess.run(user_input, shell=True)"""


def main():
    root = Path(__file__).resolve().parent / 'demo' / 'fixtures'
    with tempfile.TemporaryDirectory(prefix='prsec_demo_') as temporary:
        config = Path(temporary) / 'rules.yaml'
        config.write_text(OFFLINE_RULESET)
        for name, diff in (('vulnerable.py', PULL_REQUEST_DIFF), ('clean.py', None)):
            findings = run_semgrep([name], str(root), config=str(config))
            findings = triage(findings, {name: added_lines(diff)})
            conclusion = gate(findings)
            print(f'\n{name}: {conclusion.upper()}')
            for f in findings:
                label = 'new' if f['new'] else 'pre-existing'
                print(f"  [{f['priority']}, {label}] {f['path']}:{f['start_line']}  {f['rule_id']}")
            print(summarize_findings(findings)[1])
            print(json.dumps(to_github_annotations(findings), indent=2))
            if name == 'vulnerable.py':
                labels = {f['rule_id']: (f['priority'], f['new']) for f in findings}
                assert labels['py-subprocess-shell-true'] == ('P1', True)
                assert labels['py-weak-md5'] == ('P1', False)
                assert conclusion == 'failure'
            else:
                assert not findings and conclusion == 'success'


if __name__ == '__main__':
    main()
