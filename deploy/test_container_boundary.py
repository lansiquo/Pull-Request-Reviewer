"""Opt-in real Linux rootless Docker boundary test; never installs/configures Docker."""
import os
import sys
import tempfile
from pathlib import Path
import subprocess
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzers.semgrep_runner import docker_scan_command, verify_docker_sandbox


def main():
    if sys.platform != 'linux':
        raise SystemExit('Run this only on the approved Linux VM; no system changes were made.')
    verify_docker_sandbox()
    with tempfile.TemporaryDirectory(prefix='prsec_boundary_') as temporary:
        root=Path(temporary);source=root/'source';source.mkdir(mode=0o755)
        rules=root/'rules.yml';rules.write_text('rules: []\n');rules.chmod(0o644)
        secret=root/'host-only-marker';secret.write_text('test-only-marker');secret.chmod(0o600)
        name='prsec-boundary-'+str(os.getpid())
        image=os.environ['PRSEC_SCANNER_IMAGE']
        command=docker_scan_command(str(source),str(rules),['semgrep','--config',str(rules)],name)
        # This test image must contain /bin/sh, id, grep, and ls. An absent probe
        # tool is a failed/unrun test, never a passing isolation result.
        entry=next(i for i,arg in enumerate(command) if arg.startswith('--entrypoint='))
        command[entry]='--entrypoint=/bin/sh'
        position=command.index(image)
        command=command[:position+1]+['-eu','-c', '''
[ "$(id -u)" = 65532 ]
[ "$(ls /sys/class/net)" = lo ]
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
grep -qx 128 /sys/fs/cgroup/pids.max
grep -qx 805306368 /sys/fs/cgroup/memory.max
[ ! -e /var/run/docker.sock ]
[ ! -e /run/docker.sock ]
[ -z "${PRSEC_TEST_ONLY_SECRET:-}" ]
[ -z "${GITHUB_APP_PRIVATE_KEY:-}" ]
[ -z "${GITHUB_WEBHOOK_SECRET:-}" ]
[ ! -e "$1" ]
if touch /rootfs-write-probe 2>/dev/null; then exit 11; fi
if touch /scan/source-write-probe 2>/dev/null; then exit 12; fi
if printf changed >> /rules.yaml 2>/dev/null; then exit 13; fi
printf temporary > /tmp/write-probe
printf 'PASS: actual rootless container identity, network, capabilities, cgroups, mounts, and credential boundary.\\n'
''', 'boundary-probe', str(secret)]
        try:
            subprocess.run(command, check=True, timeout=30)
        finally:
            subprocess.run([command[0],'rm','-f',name],capture_output=True,timeout=15,check=False)
        assert rules.read_text() == 'rules: []\n'
        assert secret.read_text() == 'test-only-marker'


if __name__ == '__main__': main()
