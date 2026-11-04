"""Bounded child execution for hash-pinned synthetic lab fixtures only."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

SCENARIOS=frozenset({'access','supply','design','auth','logging','errors'})
WORKER=Path(__file__).resolve().parent/'demo'/'behavior_worker.py'
MAX_OUTPUT=65536
TIMEOUT=5


def bounded_run(command, cwd, env, timeout=TIMEOUT):
    with subprocess.Popen(command,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as child:
        output=bytearray();overflow=threading.Event()
        def drain():
            while chunk:=child.stdout.read(4096):
                if len(output)+len(chunk)>MAX_OUTPUT:
                    overflow.set();child.kill();return
                output.extend(chunk)
        thread=threading.Thread(target=drain,daemon=True);thread.start()
        try:child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill();child.wait();raise RuntimeError('Behavioral test timed out') from None
        finally:thread.join(timeout=1)
        if overflow.is_set() or thread.is_alive():raise RuntimeError('Behavioral output limit exceeded')
        if child.returncode:raise RuntimeError('Behavioral harness failed')
        return bytes(output)


def run_behavioral(scenario, variant):
    if scenario not in SCENARIOS or variant not in {'vulnerable','fixed'}:raise ValueError('Unknown authored lab fixture')
    with tempfile.TemporaryDirectory(prefix='prsec_behavior_') as temporary:
        # No inherited token, PEM path, network proxy, dotenv or Python search path.
        env={'HOME':temporary,'TMPDIR':temporary,'LANG':'C.UTF-8','PRSEC_LOAD_DOTENV':'0'}
        raw=bounded_run([sys.executable,'-I',str(WORKER),scenario,variant],temporary,env)
    data=json.loads(raw)
    assertions=data.get('assertions')
    if (data.get('scenario')!=scenario or data.get('variant')!=variant or data.get('engine')!='behavioral'
        or data.get('harness_completed') is not True or not isinstance(assertions,list) or not assertions
        or not all(isinstance(a,dict) and type(a.get('passed')) is bool and isinstance(a.get('name'),str) and isinstance(a.get('evidence'),str) for a in assertions)
        or data.get('status')!=('success' if all(a['passed'] for a in assertions) else 'failure')):
        raise RuntimeError('Incomplete behavioral evidence')
    return data
