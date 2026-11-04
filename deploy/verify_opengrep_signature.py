"""Verify v1.33.0 release checksum and exact keyless identity; no bypasses/install."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

IDENTITY = 'https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.33.0'
ISSUER = 'https://token.actions.githubusercontent.com'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact',type=Path)
    parser.add_argument('certificate',type=Path)
    parser.add_argument('signature',type=Path)
    parser.add_argument('expected_sha256',help='Digest independently obtained from the official v1.33.0 release metadata')
    args=parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{64}',args.expected_sha256):
        parser.error('Expected a lowercase SHA-256 digest')
    digest=hashlib.sha256()
    with args.artifact.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    if digest.hexdigest()!=args.expected_sha256:
        raise SystemExit('FAIL: artifact checksum mismatch')
    cosign=shutil.which(os.getenv('COSIGN_BIN','cosign'))
    if not cosign:
        raise SystemExit('Cosign unavailable; no tool was installed and verification did not pass')
    subprocess.run([cosign,'verify-blob','--cert',str(args.certificate),'--signature',str(args.signature),
        '--certificate-identity',IDENTITY,'--certificate-oidc-issuer',ISSUER,str(args.artifact)],
        check=True,timeout=120)
    print('PASS: checksum and official v1.33.0 exact-identity signature verification completed.')


if __name__ == '__main__':main()
