"""Static examples are scanned; authored behavioral fixtures run only in the bounded lab."""
import ast
import pytest
from fastapi.testclient import TestClient
import demo_web

HEADERS = {'Origin': 'http://127.0.0.1', 'X-PRSEC-Demo': '1'}


def test_catalog_has_exact_2025_categories_and_real_fixtures():
    assert len(demo_web.CATALOG) == 10
    assert [v['category'][:3] for v in demo_web.CATALOG.values()] == [f'A{i:02}' for i in range(1, 11)]
    for key, meta in demo_web.CATALOG.items():
        assert meta['source'].startswith('https://top10.owasp.org/2025/')
        for path in demo_web.SCENARIOS[key].values():
            ast.parse(path.read_text())  # Parse only: no import/exec.


@pytest.mark.parametrize('scenario', [k for k,v in demo_web.CATALOG.items() if v['mode']=='behavioral'])
@pytest.mark.parametrize('variant', ['vulnerable', 'fixed'])
def test_behavioral_examples_execute_and_return_assertions(scenario, variant, monkeypatch):
    monkeypatch.setattr(demo_web, 'run_semgrep', lambda *a, **k: pytest.fail('Behavioral examples must not call scanner'))
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    response = client.post(f'/api/scan/{scenario}/{variant}', headers=HEADERS)
    assert response.status_code == 200
    assert response.json()['status'] == ('failure' if variant == 'vulnerable' else 'success')
    assert response.json()['engine'] == 'behavioral'
    assert response.json()['harness_completed'] is True
    assert response.json()['assertions']
    assert all(a['passed'] for a in response.json()['assertions']) == (variant == 'fixed')
    assert response.json()['findings'] == []
    assert 'synthetic' in response.json()['provenance']
    data = client.get(f'/api/fixtures/{scenario}').json()
    assert data['source'][variant]
    assert '+ ' in data['diff'] or '+' in data['diff']


@pytest.mark.parametrize('variant', ['vulnerable', 'fixed'])
def test_config_fixture_live(variant, monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    result = client.post(f'/api/scan/config/{variant}', headers=HEADERS).json()
    assert result['status'] == ('failure' if variant == 'vulnerable' else 'success')
    assert {f['rule_id'] for f in result['findings']} == ({'demo-python-fastapi-debug'} if variant == 'vulnerable' else set())

@pytest.mark.parametrize('scenario', list(demo_web.CATALOG))
def test_highlights_target_existing_specific_code_lines(scenario):
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    data = client.get(f'/api/fixtures/{scenario}').json()
    assert data['review_mode'] == demo_web.CATALOG[scenario]['mode']
    for variant in ('vulnerable', 'fixed'):
        lines = data['source'][variant].splitlines()
        focus = data['highlights'][variant]
        assert focus and len(set(focus)) == len(focus)
        assert len(focus) < len(lines)
        for number in focus:
            assert 1 <= number <= len(lines)
            assert lines[number-1].strip() and not lines[number-1].lstrip().startswith('#')
