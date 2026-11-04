"""Opt-in actual Linux checks. Does not install, configure, pull, deploy or contact GitHub."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    if sys.platform!='linux' or os.geteuid()==0:
        raise SystemExit('BLOCKED: approved Linux host and non-root worker user required; no tests ran.')
    forbidden=('GITHUB_APP_PRIVATE_KEY','GITHUB_APP_PRIVATE_KEY_PATH','GITHUB_WEBHOOK_SECRET','GITHUB_WEBHOOK_SECRETS','GITHUB_TOKEN','GH_TOKEN','EXPLICIT_INSTALLATION_TOKEN','SEMGREP_APP_TOKEN')
    if any(os.getenv(key) for key in forbidden):
        raise SystemExit('BLOCKED: run acceptance without application credentials; no tests ran.')
    env={k:os.environ[k] for k in ('PATH','HOME','LANG','DOCKER_HOST','DOCKER_CONTEXT','XDG_RUNTIME_DIR','PRSEC_SCANNER_IMAGE') if k in os.environ}
    env.update(PRSEC_LOAD_DOTENV='0',PRSEC_MODE='durable',PRSEC_SCANNER_BACKEND='docker',PRSEC_SCANNER_COMMAND='semgrep',PYTHONDONTWRITEBYTECODE='1')
    results=[]
    for script in ('test_container_boundary.py','validate_scanner.py'):
        result=subprocess.run([sys.executable,str(ROOT/'deploy'/script)],cwd=ROOT,env=env,timeout=300)
        results.append({'test':script,'passed':result.returncode==0})
        if result.returncode:break
    print(json.dumps({'checks':results,'runtime_checks_passed':len(results)==2 and all(r['passed'] for r in results),
        'not_verified':['final image dependency/OS audit','separate web/worker filesystem and socket denial','container OOM/PID exhaustion and host reboot','HTTPS ingress and real GitHub delivery/recovery']},indent=2))
    raise SystemExit(0 if len(results)==2 and all(r['passed'] for r in results) else 1)

if __name__=='__main__':main()
