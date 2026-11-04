"""Offline portfolio demo: real scanner, local fixtures, no GitHub calls."""
import os
os.environ['PRSEC_LOAD_DOTENV'] = '0'
import json
import tempfile
from pathlib import Path
from app import OFFLINE_RULESET
from analyzers.semgrep_runner import run_semgrep, summarize_findings, to_github_annotations


def main():
    root = Path(__file__).resolve().parent / 'demo' / 'fixtures'
    with tempfile.TemporaryDirectory(prefix='prsec_demo_') as temporary:
        config = Path(temporary) / 'rules.yaml'
        config.write_text(OFFLINE_RULESET)
        for name in ('vulnerable.py', 'clean.py'):
            findings = run_semgrep([name], str(root), config=str(config))
            print(f'\n{name}: {"FAILURE" if findings else "SUCCESS"}')
            print(summarize_findings(findings)[1])
            print(json.dumps(to_github_annotations(findings), indent=2))
            if name == 'vulnerable.py':
                assert {'py-weak-md5', 'py-subprocess-shell-true'} <= {f['rule_id'] for f in findings}
            else:
                assert not findings


if __name__ == '__main__':
    main()
