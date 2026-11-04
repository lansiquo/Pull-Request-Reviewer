import hashlib
import json
from pathlib import Path
import shutil
import sys
import pytest
from fastapi.testclient import TestClient
import demo_behavior as lab
import demo_web


def test_rejects_arbitrary_scenario_or_variant():
    for scenario,variant in [('../../app','fixed'),('sql','fixed'),('auth','../../app')]:
        with pytest.raises(ValueError):lab.run_behavioral(scenario,variant)


def test_environment_is_stripped_and_guards_run(monkeypatch):
    for key in ('GITHUB_TOKEN','GITHUB_APP_PRIVATE_KEY','GITHUB_WEBHOOK_SECRETS','HTTP_PROXY','PYTHONPATH'):
        monkeypatch.setenv(key,'PRIVATE-SENTINEL')
    original=lab.bounded_run
    def spy(command,cwd,env,**kwargs):
        assert set(env)=={'HOME','TMPDIR','LANG','PRSEC_LOAD_DOTENV'}
        assert 'PRIVATE-SENTINEL' not in repr(env)
        assert '-I' in command
        assert Path(cwd).is_dir()
        return original(command,cwd,env,**kwargs)
    monkeypatch.setattr(lab,'bounded_run',spy)
    result=lab.run_behavioral('auth','fixed')
    assert result['status']=='success'
    assert all(result['boundary'].values())
    assert 'PRIVATE-SENTINEL' not in json.dumps(result)


def copied_worker(tmp_path):
    worker=tmp_path/'behavior_worker.py';shutil.copy(lab.WORKER,worker)
    shutil.copy(lab.WORKER.parent/'behavior_hashes.json',tmp_path/'behavior_hashes.json')
    shutil.copytree(lab.WORKER.parent/'showcase',tmp_path/'showcase')
    return worker


def test_changed_fixture_refused_before_execution(tmp_path,monkeypatch):
    worker=copied_worker(tmp_path)
    (tmp_path/'showcase/errors_fixed.py').write_text('raise Exception("MUST NOT EXECUTE")\n')
    monkeypatch.setattr(lab,'WORKER',worker)
    with pytest.raises(RuntimeError,match='harness failed'):lab.run_behavioral('errors','fixed')


def test_verdict_depends_on_executed_code_not_variant_name(tmp_path,monkeypatch):
    worker=copied_worker(tmp_path)
    source=(tmp_path/'showcase/errors_fixed.py').read_bytes()
    (tmp_path/'showcase/errors_vulnerable.py').write_bytes(source)
    manifest=tmp_path/'behavior_hashes.json';data=json.loads(manifest.read_text())
    data['errors_vulnerable.py']=hashlib.sha256(source).hexdigest();manifest.write_text(json.dumps(data))
    monkeypatch.setattr(lab,'WORKER',worker)
    assert lab.run_behavioral('errors','vulnerable')['status']=='success'


def test_timeout_and_output_are_bounded(tmp_path):
    with pytest.raises(RuntimeError,match='timed out'):
        lab.bounded_run([sys.executable,'-I','-c','while True: pass'],str(tmp_path),{},timeout=.1)
    with pytest.raises(RuntimeError,match='output limit'):
        lab.bounded_run([sys.executable,'-I','-c','print("x" * 1000000)'],str(tmp_path),{})


def test_harness_error_does_not_become_a_pass(monkeypatch):
    def fail(*args):raise RuntimeError('PRIVATE-SENTINEL')
    monkeypatch.setattr(demo_web,'run_behavioral',fail)
    client=TestClient(demo_web.app,base_url='http://127.0.0.1')
    response=client.post('/api/scan/auth/fixed',headers={'Origin':'http://127.0.0.1','X-PRSEC-Demo':'1'})
    assert response.status_code==503
    assert response.json()['status']=='error'
    assert 'PRIVATE-SENTINEL' not in response.text
    assert demo_web.SCAN_LOCK.acquire(blocking=False)
    demo_web.SCAN_LOCK.release()
