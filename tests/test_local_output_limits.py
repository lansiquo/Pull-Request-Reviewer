"""Exercise public local scan entrypoint with real hostile-output processes."""
import sys
import json
import subprocess

import pytest
from analyzers import semgrep_runner as runner


def test_local_scan_bounds_output_before_json_parsing(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'main.py').write_text('print(1)')
    executable = tmp_path / 'fake-scanner'
    executable.write_text('#!' + sys.executable + '\nimport sys\nsys.stdout.write("x" * 10000000)\n')
    executable.chmod(0o755)
    monkeypatch.setenv('SEMGREP_BIN', str(executable))
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    monkeypatch.setenv('PRSEC_MODE', 'local')
    with pytest.raises(runner.SemgrepInvocationError, match='output exceeded'):
        runner.run_semgrep(['main.py'], str(source), config='/trusted/rules.yaml')


def test_findings_exit_with_empty_results_never_passes(tmp_path, monkeypatch):
    (tmp_path / 'main.py').write_text('print(1)')
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/scanner')
    data = {'results': [], 'errors': [], 'paths': {'scanned': ['main.py']}}
    monkeypatch.setattr(runner, '_bounded_container_run', lambda **k:
                        subprocess.CompletedProcess([], 1, json.dumps(data), ''))
    with pytest.raises(runner.SemgrepInvocationError, match='contradicts'):
        runner.run_semgrep(['main.py'], str(tmp_path), config='/trusted/rules.yaml')
