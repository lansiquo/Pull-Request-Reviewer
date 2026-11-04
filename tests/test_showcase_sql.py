"""Live Semgrep checks for the trusted SQL showcase, never executing its source."""
from pathlib import Path
import pytest
from analyzers.semgrep_runner import run_semgrep
from demo_rules import SHOWCASE_RULESET

@pytest.mark.parametrize('source,expected', [
    ('db.execute("SELECT name FROM customers WHERE name = " + user_name)', True),
    ('db.execute("SELECT name FROM customers WHERE name = " + user_name) # nosemgrep', True),
    ('db.execute("SELECT name FROM customers WHERE name = ?", (user_name,))', False),
    ('db.execute("SELECT name FROM customers")', False),
])
def test_demo_sql_rule_live(tmp_path, source, expected, monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    (tmp_path / 'lookup.py').write_text(source + '\n')
    rules = tmp_path / 'trusted.yaml'
    rules.write_text(SHOWCASE_RULESET)
    findings = run_semgrep(['lookup.py'], str(tmp_path), config=str(rules))
    assert bool(findings) == expected
    if expected:
        assert {f['rule_id'] for f in findings} == {'demo-python-sql-string-concatenation'}
        assert findings[0]['start_line'] == 1
