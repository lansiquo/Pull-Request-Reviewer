import hashlib
import subprocess
import sys
import pytest
from deploy import verify_opengrep_signature as verification


def test_signature_policy_uses_exact_identity_and_issuer(tmp_path, monkeypatch):
    artifact=tmp_path/'artifact';artifact.write_bytes(b'test-artifact')
    monkeypatch.setattr(sys,'argv',['verify',str(artifact),'public.cert','public.sig',hashlib.sha256(artifact.read_bytes()).hexdigest()])
    monkeypatch.setattr(verification.shutil,'which',lambda _: '/verified/cosign')
    calls=[]
    monkeypatch.setattr(verification.subprocess,'run',lambda command,**kwargs:calls.append((command,kwargs)))
    verification.main()
    command, options=calls[0]
    assert command[command.index('--certificate-identity')+1]==verification.IDENTITY
    assert command[command.index('--certificate-oidc-issuer')+1]==verification.ISSUER
    assert options['check'] is True
    assert not any('insecure' in argument or 'ignore' in argument for argument in command)


def test_signature_policy_rejects_bad_hash_before_cosign(tmp_path, monkeypatch):
    artifact=tmp_path/'artifact';artifact.write_bytes(b'test-artifact')
    monkeypatch.setattr(sys,'argv',['verify',str(artifact),'public.cert','public.sig','0'*64])
    def forbidden(*args,**kwargs):raise AssertionError('Cosign must not run')
    monkeypatch.setattr(verification.subprocess,'run',forbidden)
    with pytest.raises(SystemExit,match='checksum mismatch'):
        verification.main()
