"""Read-only, role-specific deployment checks. Never loads dotenv or prints values."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from queue_maintenance import inspect_queue


def validate(env,role):
    errors=[]
    def require(ok,label):
        if not ok:errors.append(label)
    require(env.get('PRSEC_MODE')=='durable','PRSEC_MODE must be durable')
    require(env.get('PRSEC_LOAD_DOTENV')=='0','dotenv loading must be disabled')
    require(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',env.get('PRSEC_ALLOWED_REPOSITORY',''))),'explicit repository scope required')
    require(env.get('PRSEC_ALLOWED_INSTALLATION_ID','').isdigit() and int(env.get('PRSEC_ALLOWED_INSTALLATION_ID') or 0)>0,'positive installation ID required')
    require(env.get('GITHUB_API','https://api.github.com')=='https://api.github.com','unexpected GitHub API destination')
    require(env.get('PRSEC_SHARED_STATE')=='1','separate identities require shared state group')
    require(not env.get('EXPLICIT_INSTALLATION_TOKEN') and env.get('FORCE_EXPLICIT_TOKEN')!='1','explicit token fallback must be disabled')
    path=Path(env.get('PRSEC_JOB_DB',''))
    require(bool(env.get('PRSEC_JOB_DB')) and path.is_absolute(),'absolute queue path required')
    if path.is_absolute():
        parent=path.parent
        if parent.is_dir():
            mode=stat.S_IMODE(parent.stat().st_mode)
            require(mode&0o777==0o770 and (sys.platform!='linux' or bool(mode&stat.S_ISGID)),'queue directory requires mode 2770 on Linux (770 on macOS)')
            require(parent.stat().st_gid in {os.getegid(),*os.getgroups()},'service user must belong to queue group')
        else:errors.append('queue directory must be provisioned')
        if path.exists() or path.is_symlink():
            require(not path.is_symlink() and path.is_file() and stat.S_IMODE(path.stat().st_mode)==0o660,'queue file must be regular mode 660')
            try:
                report=inspect_queue(path)
                require(not report['legacy_active'] and not report['invalid_active'],'quarantine/replay legacy or malformed active jobs before deployment')
            except Exception:errors.append('queue integrity/schema inspection failed')
    if role=='web':
        require(bool(env.get('GITHUB_WEBHOOK_SECRET') or env.get('GITHUB_WEBHOOK_SECRETS')),'webhook secret required by web role')
        require(not env.get('GITHUB_APP_PRIVATE_KEY_PATH') and not env.get('GITHUB_APP_PRIVATE_KEY'),'web role must not receive App private key configuration')
        require(not env.get('DOCKER_HOST') and not env.get('DOCKER_CONTEXT'),'web role must not receive Docker connection configuration')
    else:
        require(env.get('GITHUB_APP_ID','').isdigit() and int(env.get('GITHUB_APP_ID') or 0)>0,'positive App ID required')
        require(not env.get('GITHUB_WEBHOOK_SECRET') and not env.get('GITHUB_WEBHOOK_SECRETS'),'worker role must not receive webhook secret')
        require(not env.get('GITHUB_APP_PRIVATE_KEY'),'use protected PEM file, not inline private key')
        key=Path(env.get('GITHUB_APP_PRIVATE_KEY_PATH',''))
        require(bool(env.get('GITHUB_APP_PRIVATE_KEY_PATH')) and key.is_absolute(),'absolute PEM path required')
        if key.is_file():
            st=key.stat();require(not key.is_symlink() and st.st_uid==os.geteuid() and not stat.S_IMODE(st.st_mode)&0o077,'PEM must be owned by worker and inaccessible to group/others')
        else:errors.append('worker PEM file unavailable')
        require(env.get('PRSEC_SCANNER_BACKEND')=='docker','worker requires Docker scanner backend')
        require(env.get('PRSEC_SCANNER_COMMAND','semgrep')=='semgrep','approved scanner remains Semgrep')
        require(bool(re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}',env.get('PRSEC_SCANNER_IMAGE',''))),'audited image must be pinned by digest')
    return errors


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--role',choices=['web','worker'],required=True)
    args=parser.parse_args();errors=validate(os.environ,args.role)
    if not errors and args.role=='worker':
        try:
            from analyzers.semgrep_runner import verify_docker_sandbox
            verify_docker_sandbox()
        except Exception:errors.append('existing rootless Docker runtime or pinned image unavailable')
    print(json.dumps({'configuration_ready':not errors,'role':args.role,'errors':errors,
        'scope':'Configuration and local runtime only; image audit, cross-user denial, HTTPS and live GitHub acceptance are separate gates.'},indent=2))
    raise SystemExit(1 if errors else 0)

if __name__=='__main__':main()
