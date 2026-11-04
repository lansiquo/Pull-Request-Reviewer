"""Real static scans only; no fixture code or payloads are executed."""
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import demo_web
from demo_rules import SHOWCASE_RULESET
from analyzers.semgrep_runner import run_semgrep

@pytest.mark.parametrize('source,expected', [
    ("subprocess.run('echo ' + message, shell=True)", 'demo-python-shell-command'),
    ("subprocess.run('echo ' + message, shell=True) # nosemgrep", 'demo-python-shell-command'),
    ("subprocess.run(['/bin/echo', message], shell=False, check=True)", None),
    ('yaml.load(text, Loader=yaml.Loader)', 'demo-python-unsafe-yaml'),
    ('yaml.load(text, Loader=yaml.UnsafeLoader)', 'demo-python-unsafe-yaml'),
    ('yaml.unsafe_load(text)', 'demo-python-unsafe-yaml'),
    ('yaml.safe_load(text)', None),
    ('yaml.load(text, Loader=yaml.SafeLoader)', None),
])
def test_command_yaml_rules_live(tmp_path, source, expected, monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    (tmp_path / 'sample.py').write_text(source + '\n')
    rules = tmp_path / 'trusted.yaml'; rules.write_text(SHOWCASE_RULESET)
    findings = run_semgrep(['sample.py'], str(tmp_path), config=str(rules))
    assert {f['rule_id'] for f in findings} == ({expected} if expected else set())

@pytest.mark.parametrize('scenario', ['sql', 'command', 'yaml', 'tls'])
def test_only_selected_bundled_scenario_reaches_scanner(scenario, monkeypatch):
    def scan(paths, root, **kwargs):
        assert paths == [demo_web.SCENARIOS[scenario]['fixed'].name]
        assert Path(root) == demo_web.ROOT / 'showcase'
        return []
    monkeypatch.setattr(demo_web, 'run_semgrep', scan)
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    assert client.get('/api/fixtures/'+scenario).status_code == 200
    result = client.post('/api/scan/'+scenario+'/fixed', headers={'Origin':'http://127.0.0.1','X-PRSEC-Demo':'1'})
    assert result.json()['scenario'] == scenario
    assert result.json()['status'] == 'success'


def test_unknown_scenario_rejected_before_scan(monkeypatch):
    monkeypatch.setattr(demo_web, 'run_semgrep', lambda *a, **k: pytest.fail('must not scan'))
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    assert client.get('/api/fixtures/unknown').status_code == 404
    assert client.post('/api/scan/unknown/fixed', headers={'Origin':'http://127.0.0.1','X-PRSEC-Demo':'1'}).status_code == 404

@pytest.mark.parametrize('source,expected', [
    ('requests.get(url, verify=False, timeout=5)', True),
    ('requests.post(url, verify=False)', True),
    ('requests.request("GET", url, verify=False)', True),
    ('requests.get(url, verify=False) # nosemgrep', True),
    ('requests.get(url, verify=True, timeout=5)', False),
    ('requests.get(url, timeout=5)', False),
    ('other_client.get(url, verify=False)', False),
])
def test_tls_rule_live(tmp_path, source, expected, monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    (tmp_path / 'sample.py').write_text(source + '\n')
    rules = tmp_path / 'trusted.yaml'
    rules.write_text(SHOWCASE_RULESET)
    findings = run_semgrep(['sample.py'], str(tmp_path), config=str(rules))
    assert {f['rule_id'] for f in findings} == ({'demo-python-disabled-tls-verification'} if expected else set())

@pytest.mark.parametrize('scenario', ['sql', 'command', 'yaml', 'tls'])
@pytest.mark.parametrize('variant', ['vulnerable', 'fixed'])
def test_bundled_scenarios_live(scenario, variant, monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    response = client.post(f'/api/scan/{scenario}/{variant}', headers={'Origin':'http://127.0.0.1','X-PRSEC-Demo':'1'})
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == ('failure' if variant == 'vulnerable' else 'success')
    assert len(data['findings']) == (1 if variant == 'vulnerable' else 0)
