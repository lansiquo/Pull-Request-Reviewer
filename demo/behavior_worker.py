"""Execute only hash-pinned, authored lab fixtures with synthetic adapters.
Not an OS sandbox and never suitable for arbitrary/PR code.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

SCENARIOS = {'access', 'supply', 'design', 'auth', 'logging', 'errors'}
ROOT = Path(__file__).resolve().parent


def boundary(temporary):
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    def guard(event, args):
        if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in {'os.system', 'os.fork', 'os.posix_spawn'}:
            raise PermissionError('Lab operation forbidden')
        if event == 'open':
            if not isinstance(args[0], (str, bytes, os.PathLike)):
                raise PermissionError('Lab file operation forbidden')
            path = Path(os.fsdecode(args[0])).resolve()
            if not path.is_relative_to(temporary):
                raise PermissionError('Lab file operation forbidden')
    sys.addaudithook(guard)
    for event, args in [('socket.connect', (None, None)), ('subprocess.Popen', (None, None, None, None)), ('open', ('/outside-lab-sentinel', 'r', 0))]:
        try:
            sys.audit(event, *args)
        except PermissionError:
            continue
        raise RuntimeError('Boundary guard failed')


def execute(scenario, module):
    results = []
    def check(name, ok, evidence):
        results.append({'name': name, 'passed': bool(ok), 'evidence': evidence})
    if scenario == 'access':
        class Invoice:
            owner_id = 1
            def to_dict(self): return {'amount': 25}
        invoices = {9: Invoice()}
        owner = module['read_invoice'](invoices, SimpleNamespace(id=1), 9)
        denied = False
        try: module['read_invoice'](invoices, SimpleNamespace(id=2), 9)
        except PermissionError: denied = True
        check('Owner can read their invoice', owner == {'amount': 25}, 'Synthetic owner request evaluated')
        check('Another user cannot read the invoice', denied, 'Denied' if denied else 'Invoice disclosed to the other synthetic user')
    elif scenario == 'supply':
        class Pipeline:
            def __init__(self, approved=True, tampered=False):
                self.approved = approved
                self.artifact = b'approved synthetic artifact' if not tampered else b'changed synthetic artifact'
                self.manifest = {'sha256': hashlib.sha256(b'approved synthetic artifact').hexdigest(), 'approved': approved, 'audit_clear': True}
                self.gates = set()
            def install(self, filename): self.gates.add('unverified-install')
            def require_reviewed_lock(self, filename):
                if not self.manifest['approved']: raise ValueError('Unapproved manifest')
                self.gates.add('lock')
            def verify_dependency_provenance(self):
                if not self.approved: raise ValueError('Unapproved source')
                self.gates.add('provenance')
            def audit_all_dependencies(self):
                if not self.manifest['audit_clear']: raise ValueError('Synthetic audit failed')
                self.gates.add('audit')
            def install_locked(self, require_hashes):
                if not require_hashes or hashlib.sha256(self.artifact).hexdigest() != self.manifest['sha256']: raise ValueError('Artifact mismatch')
                self.gates.add('hashes')
            def record_sbom(self): self.gates.add('inventory')
            def package(self): return {'built': True, 'gates': sorted(self.gates)}
        approved = module['build_release'](Pipeline())
        check('Approved synthetic artifact can build', approved['built'], 'No packages installed or artifact code executed')
        for title,pipeline in [('Unapproved manifest rejected', Pipeline(approved=False)), ('Tampered artifact rejected', Pipeline(tampered=True))]:
            rejected=False
            try: module['build_release'](pipeline)
            except ValueError: rejected=True
            check(title,rejected,'Release rejected' if rejected else 'Release built despite missing trust')
    elif scenario == 'design':
        class Store:
            def __init__(self): self.lock=threading.RLock(); self.redemptions=set(); self.balance=0
            @contextlib.contextmanager
            def transaction(self):
                with self.lock:
                    before=(set(self.redemptions),self.balance)
                    try: yield
                    except Exception:
                        self.redemptions,self.balance=before
                        raise
            def insert_redemption_unique(self,user,coupon):
                key=(user,coupon)
                if key in self.redemptions:return False
                self.redemptions.add(key);return True
            def credit(self,user,value):
                with self.lock:self.balance+=value
        user=SimpleNamespace(id=1);coupon=SimpleNamespace(id=2,value=10)
        store=Store()
        def redeem():
            try:module['redeem_coupon'](store,user,coupon);return True
            except ValueError:return False
        first=redeem();second=redeem()
        check('Second redemption denied',first and not second and store.balance==10,f'Credit total after two requests: {store.balance}')
        store=Store();barrier=threading.Barrier(2)
        def concurrent(_):barrier.wait(timeout=1);return redeem()
        with ThreadPoolExecutor(max_workers=2) as pool:outcomes=list(pool.map(concurrent,range(2)))
        check('Concurrent requests issue credit once',sum(outcomes)==1 and store.balance==10,f'Accepted requests: {sum(outcomes)}; credit total: {store.balance}')
    elif scenario == 'auth':
        class Sessions:
            def __init__(self):self.rows={'synthetic-prelogin':None};self.lock=threading.Lock()
            def bind_user(self,key,user):self.rows[key]=user
            def rotate_and_bind(self,key,user):
                with self.lock:
                    self.rows.pop(key,None)
                    fresh=secrets.token_urlsafe(24)
                    self.rows[fresh]=user
                    return fresh
        sessions=Sessions();auth=SimpleNamespace(verify=lambda credentials:SimpleNamespace(id=1))
        fresh=module['finish_login'](auth,sessions,'synthetic-prelogin',{'synthetic':True})
        check('Old session invalidated','synthetic-prelogin' not in sessions.rows,'Old identifier absent' if 'synthetic-prelogin' not in sessions.rows else 'Old identifier remains valid')
        check('New authenticated session is distinct',fresh!='synthetic-prelogin' and sessions.rows.get(fresh)==1,'Synthetic session state inspected; identifiers not included')
    elif scenario == 'logging':
        class Audit:
            def __init__(self):self.events=[];self.alerts=[]
            def record(self,**fields):
                # Synthetic structured sink with strict allowed keys and local threshold.
                if set(fields)!={'event','request_id'}:raise ValueError('Unexpected log field')
                self.events.append(json.loads(json.dumps(fields)))
                if len(self.events)==2:self.alerts.append({'type':'repeated_access_denial','count':2})
        audit=Audit()
        responses=[module['denied_access'](audit,'synthetic-request-'+str(i)) for i in range(2)]
        check('Both requests remain denied',all(r['status']==403 for r in responses),'Two synthetic denied requests')
        check('Structured denials recorded without private fields',len(audit.events)==2 and all(set(e)=={'event','request_id'} and e['event']=='access_denied' for e in audit.events),f'Structured records: {len(audit.events)}; allowed fields only')
        check('Repeated denials trigger a local test alert',len(audit.alerts)==1 and audit.alerts[0]['count']==2,f'In-memory test alerts: {len(audit.alerts)}; nothing sent externally')
    elif scenario == 'errors':
        normal=SimpleNamespace(allows=lambda *a:True)
        def timeout(*args):raise TimeoutError('Synthetic policy timeout')
        allowed=module['may_download'](normal,'synthetic-user','synthetic-document')
        decision=module['may_download'](SimpleNamespace(allows=timeout),'synthetic-user','synthetic-document')
        check('Healthy explicit allow is honored',allowed is True,'Synthetic healthy policy result')
        check('Policy timeout denies access',decision is False,'Denied on timeout' if decision else 'Denied on timeout')
        if decision is not False:results[-1]['evidence']='Access granted despite policy timeout'
    return results


def main():
    scenario,variant=sys.argv[1:]
    if scenario not in SCENARIOS or variant not in {'vulnerable','fixed'}:raise ValueError('Unknown trusted fixture')
    name=f'{scenario}_{variant}.py'
    source=(ROOT/'showcase'/name).read_bytes()
    manifest=json.loads((ROOT/'behavior_hashes.json').read_text())
    if hashlib.sha256(source).hexdigest()!=manifest[name]:raise ValueError('Trusted fixture changed; review and pin it before execution')
    code=compile(source,name,'exec')
    boundary(Path.cwd().resolve())
    start=time.monotonic();module={};exec(code,module)
    assertions=execute(scenario,module)
    print(json.dumps({'status':'success' if all(a['passed'] for a in assertions) else 'failure',
        'engine':'behavioral','scenario':scenario,'variant':variant,'assertions':assertions,
        'elapsed_ms':round((time.monotonic()-start)*1000,2),'harness_completed':True,
        'boundary':{'network_blocked':True,'process_creation_blocked':True,'outside_files_blocked':True}}))

if __name__=='__main__':main()
