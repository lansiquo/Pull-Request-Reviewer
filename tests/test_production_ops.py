import hashlib
import hmac
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
import app
import worker
from job_store import JobStore
from test_jobs import configure,payload


def push(sha='c'*40,ref='refs/heads/main',deleted=False):
    return {'ref':ref,'after':sha,'deleted':deleted,'repository':{'owner':{'login':'lansiquo'},'name':'PR_Reviewer'},'installation':{'id':80788483}}


def deliver_push(body):
    raw=json.dumps(body).encode()
    return TestClient(app.app).post('/webhook',content=raw,headers={'X-GitHub-Event':'push','X-GitHub-Delivery':'push-1','X-Hub-Signature-256':'sha256='+hmac.new(b'testsecret',raw,hashlib.sha256).hexdigest()})


def setup(tmp_path,monkeypatch):
    configure(monkeypatch);monkeypatch.setattr(app,'JOB_DB',str(tmp_path/'queue.db'))
    return JobStore(app.JOB_DB)


def test_push_is_durable_and_deduplicated_without_network(tmp_path,monkeypatch):
    store=setup(tmp_path,monkeypatch)
    response=deliver_push(push());assert response.status_code==200
    assert response.json()['queued']
    assert not deliver_push(push()).json()['queued']
    assert JobStore(app.JOB_DB).claim()['payload']['kind']=='base_push'


def test_legacy_job_cannot_touch_github(tmp_path,monkeypatch):
    store=setup(tmp_path,monkeypatch);legacy=payload();legacy.pop('base_sha',None);legacy.pop('base_ref',None)
    key,_=store.enqueue(legacy);job=store.claim()
    monkeypatch.setattr(app,'_get_installation_token',lambda *a:pytest.fail('Legacy job must fail before credentials/API'))
    worker.process_job(store,job)
    assert store.status()['recent_failures'][0]['error']=='legacy_base_context_missing'


def pr_snapshot(number=1,sha='c'*40):
    from test_lifecycle_observability import event
    return {**event(base_sha=sha)['pull_request'],'number':number,'state':'open'}


def test_push_expands_once_into_current_base_context_after_restart(tmp_path,monkeypatch):
    store=setup(tmp_path,monkeypatch)
    first,_=store.enqueue(payload());store.claim();store.finish(first)
    assert deliver_push(push()).json()['queued']
    store=JobStore(app.JOB_DB);job=store.claim()
    monkeypatch.setattr(app,'_get_installation_token',lambda *a:'fake')
    def read(url,token,params,**kwargs):
        assert url.endswith('/pulls') and params['base']=='main' and params['state']=='open'
        return [pr_snapshot()]
    monkeypatch.setattr(app,'_get_json',read)
    monkeypatch.setattr(app,'_post_json',lambda *a,**k:pytest.fail('Expansion must not create Checks'))
    worker.process_job(store,job)
    child=JobStore(app.JOB_DB).claim()
    assert child['payload']['base_sha']=='c'*40 and child['payload']['head_sha']=='a'*40
    assert child['id']!=first
    assert not store.expand(job['id'],[child['payload']])
    assert store.status()['counts']=={'queued':0,'running':1,'done':2,'failed':0}


def test_push_expansion_rolls_back_at_capacity_and_can_resume(tmp_path,monkeypatch):
    store=setup(tmp_path,monkeypatch);deliver_push(push());job=store.claim()
    children=[payload()|{'pr':n} for n in (1,2)]
    with pytest.raises(OverflowError):store.expand(job['id'],children,capacity=1)
    assert store.status()['counts']['running']==1 and store.status()['counts']['queued']==0
    assert store.expand(job['id'],children,capacity=2)
    assert store.status()['counts']['queued']==2


def test_concurrent_expansion_has_one_commit(tmp_path,monkeypatch):
    store=setup(tmp_path,monkeypatch);deliver_push(push());job=store.claim()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(lambda _:JobStore(app.JOB_DB).expand(job['id'],[payload()]),range(6)))
    assert sum(results)==1
    assert store.status()['counts']['queued']==1


@pytest.mark.parametrize('change,status',[
    ({'ref':'refs/tags/v1'},200),({'deleted':True,'after':'0'*40},200),
    ({'ref':'refs/heads/../bad'},400),({'after':'not-a-sha'},400),
    ({'installation':{'id':123}},403),({'repository':{'owner':{'login':'other'},'name':'repo'}},403)])
def test_push_scope_and_ref_validation(tmp_path,monkeypatch,change,status):
    store=setup(tmp_path,monkeypatch)
    result=deliver_push(push()|change)
    assert result.status_code==status
    assert store.claim() is None


def test_push_enumeration_rate_limit_keeps_parent_recoverable(tmp_path,monkeypatch):
    import requests
    store=setup(tmp_path,monkeypatch);deliver_push(push());job=store.claim()
    monkeypatch.setattr(app,'_get_installation_token',lambda *a:'fake')
    def limited(*a,**k):
        response=requests.Response();response.status_code=429
        raise app.GitHubRateLimitError(response,900)
    monkeypatch.setattr(app,'_get_json',limited)
    with pytest.raises(app.GitHubRateLimitError) as raised:worker.process_job(store,job)
    store.retry(job['id'],'GitHubRateLimitError',retry_after=raised.value.retry_after)
    assert JobStore(app.JOB_DB).claim() is None
    assert store.status()['cooldown_until'] is not None
    assert store.status()['counts']['queued']==1


def test_push_over_bound_never_partially_enqueues(tmp_path,monkeypatch):
    store=setup(tmp_path,monkeypatch);deliver_push(push());job=store.claim()
    monkeypatch.setattr(app,'_get_installation_token',lambda *a:'fake')
    monkeypatch.setattr(app,'_get_json',lambda *a,**k:[pr_snapshot(n) for n in range(1,102)])
    with pytest.raises(OverflowError):worker.process_job(store,job)
    assert store.status()['counts']['queued']==0


def test_backup_restore_includes_wal_state_and_never_overwrites(tmp_path):
    from queue_maintenance import snapshot,inspect_queue
    source=tmp_path/'source.db';store=JobStore(source)
    key,_=store.enqueue(payload());job=store.claim();store.set_check(key,123);store.retry(key,'ConnectionError',retry_after=900)
    with store.connect() as active:
        active.execute('INSERT OR REPLACE INTO worker_health VALUES (1,123)');active.commit()
        backup=tmp_path/'backup.db';snapshot(source,backup)
    assert backup.stat().st_mode&0o777==0o600
    restored=tmp_path/'restored.db';snapshot(backup,restored)
    assert inspect_queue(restored)['counts']=={'queued':1}
    recovered=JobStore(restored)
    assert recovered.status()['cooldown_until'] is not None
    with recovered.connect() as db:
        row=db.execute('SELECT check_id,attempts,error FROM jobs').fetchone()
        assert tuple(row)==(123,1,'ConnectionError')
    old=backup.read_bytes()
    with pytest.raises(FileExistsError):snapshot(source,backup)
    assert backup.read_bytes()==old


def test_future_schema_refused_without_modification(tmp_path):
    from queue_maintenance import snapshot
    path=tmp_path/'future.db';JobStore(path)
    with sqlite3.connect(path) as db:db.execute('PRAGMA user_version=99')
    with pytest.raises(RuntimeError):JobStore(path)
    with pytest.raises(ValueError):snapshot(path,tmp_path/'copy.db')
    assert not (tmp_path/'copy.db').exists()
    with sqlite3.connect(path) as db:assert db.execute('PRAGMA user_version').fetchone()[0]==99


def test_legacy_schema_upgrade_and_quarantine_preserve_identity(tmp_path):
    from queue_maintenance import inspect_queue
    path=tmp_path/'legacy.db';store=JobStore(path);p=payload();p.pop('base_sha');p.pop('base_ref')
    key,_=store.enqueue(p);store.set_check(key,456)
    with store.connect() as db:db.execute('PRAGMA user_version=0')
    assert inspect_queue(path)['legacy_active']==1
    upgraded=JobStore(path);assert upgraded.quarantine_legacy()==1
    assert inspect_queue(path)['schema_version']==1 and inspect_queue(path)['legacy_active']==0
    row=upgraded.status()['recent_failures'][0]
    assert row['id']==key and row['check_id']==456 and row['error']=='legacy_base_context_missing'
    assert upgraded.claim() is None


def test_environment_validator_never_exposes_values(tmp_path):
    from deploy.check_environment import validate
    directory=tmp_path/'queue';directory.mkdir(mode=0o770);directory.chmod(0o2770)
    env={'PRSEC_MODE':'durable','PRSEC_LOAD_DOTENV':'0','PRSEC_SHARED_STATE':'1','PRSEC_JOB_DB':str(directory/'jobs.db'),
         'PRSEC_ALLOWED_REPOSITORY':'lansiquo/PR_Reviewer','PRSEC_ALLOWED_INSTALLATION_ID':'80788483','GITHUB_WEBHOOK_SECRET':'PRIVATE-SENTINEL'}
    assert validate(env,'web')==[]
    env['GITHUB_APP_PRIVATE_KEY']='PRIVATE-SENTINEL';env['DOCKER_HOST']='PRIVATE-SENTINEL'
    errors=validate(env,'web');assert errors
    assert 'PRIVATE-SENTINEL' not in str(errors)


def test_corrupt_backup_is_not_published(tmp_path):
    from queue_maintenance import snapshot
    path=tmp_path/'broken.db';path.write_bytes(b'not sqlite')
    with pytest.raises(sqlite3.Error):snapshot(path,tmp_path/'copy.db')
    assert not (tmp_path/'copy.db').exists()


def test_incomplete_legacy_schema_not_silently_promoted(tmp_path):
    path=tmp_path/'incomplete.db'
    with sqlite3.connect(path) as db:db.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY)')
    with pytest.raises(RuntimeError,match='unsupported migration'):JobStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==0
        assert len(db.execute('PRAGMA table_info(jobs)').fetchall())==1


def test_legacy_worker_recovery_quarantines_without_erasing_check(tmp_path):
    path=tmp_path/'queue.db';store=JobStore(path);p=payload();p.pop('base_sha')
    key,_=store.enqueue(p);store.claim();store.set_check(key,111)
    store=JobStore(path);store.recover()
    assert store.claim() is None
    assert store.status()['recent_failures'][0]['check_id']==111
