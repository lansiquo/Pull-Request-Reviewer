"""Service-owned rules shared with the credential-free local showcase."""
OFFLINE_RULESET = r"""
rules:
  # Crypto: weak hashes
  - id: py-weak-md5
    message: Use of weak hash (md5)
    severity: ERROR
    languages: [python]
    pattern: hashlib.md5(...)
    metadata:
      cwe: CWE-327
      owasp: A02:2021

  - id: py-weak-sha1
    message: Use of weak hash (sha1)
    severity: ERROR
    languages: [python]
    pattern: hashlib.sha1(...)
    metadata:
      cwe: CWE-327
      owasp: A02:2021

  # YAML / Deserialization
  - id: py-unsafe-yaml-load
    message: yaml.load without a safe loader
    severity: ERROR
    languages: [python]
    patterns:
      - pattern: yaml.load(...)
      - pattern-not: yaml.load(..., Loader=yaml.SafeLoader)
      - pattern-not: yaml.load(..., Loader=SafeLoader)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  - id: py-unsafe-yaml-unsafe-load
    message: yaml.unsafe_load used
    severity: ERROR
    languages: [python]
    pattern: yaml.unsafe_load(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  - id: py-insecure-deserialization-pickle-loads
    message: Insecure deserialization via pickle.loads
    severity: ERROR
    languages: [python]
    pattern: pickle.loads(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  - id: py-insecure-deserialization-pickle-load
    message: Insecure deserialization via pickle.load
    severity: ERROR
    languages: [python]
    pattern: pickle.load(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  # Command Execution
  - id: py-os-system
    message: os.system() can lead to command injection
    severity: ERROR
    languages: [python]
    pattern: os.system(...)
    metadata:
      cwe: CWE-78
      owasp: A03:2021

  - id: py-os-popen
    message: os.popen*() can lead to command injection
    severity: ERROR
    languages: [python]
    pattern-either:
      - pattern: os.popen(...)
      - pattern: os.popen2(...)
      - pattern: os.popen3(...)
      - pattern: os.popen4(...)
    metadata:
      cwe: CWE-78
      owasp: A03:2021

  - id: py-subprocess-shell-true
    message: subprocess with shell=True (possible injection)
    severity: ERROR
    languages: [python]
    patterns:
      - pattern: subprocess.$F(..., shell=True, ...)
      - metavariable-pattern:
          metavariable: $F
          pattern-either:
            - pattern: run
            - pattern: call
            - pattern: Popen
            - pattern: check_output
    metadata:
      cwe: CWE-78
      owasp: A03:2021

  - id: py-dangerous-eval
    message: Dangerous use of eval()
    severity: ERROR
    languages: [python]
    pattern: eval(...)
    metadata:
      cwe: CWE-95
      owasp: A03:2021

  - id: py-dangerous-exec
    message: Dangerous use of exec()
    severity: ERROR
    languages: [python]
    pattern: exec(...)
    metadata:
      cwe: CWE-95
      owasp: A03:2021

  # HTTP / TLS
  - id: py-requests-disable-verify
    message: TLS certificate verification disabled
    severity: ERROR
    languages: [python]
    pattern: requests.$F(..., verify=False, ...)
    metadata:
      cwe: CWE-295
      owasp: A02:2021

  # Randomness / temp files
  - id: py-random-for-secrets
    message: random module is not cryptographically secure
    severity: WARNING
    languages: [python]
    pattern: random.$F(...)
    metadata:
      cwe: CWE-338

  - id: py-tempfile-mktemp
    message: tempfile.mktemp() is insecure; use NamedTemporaryFile/mkstemp
    severity: WARNING
    languages: [python]
    pattern: tempfile.mktemp(...)
    metadata:
      cwe: CWE-377

  # Archives (handle direct and context-manager forms)
  - id: py-tarfile-extractall
    message: tarfile.extractall() can allow path traversal
    severity: ERROR
    languages: [python]
    pattern-either:
      - pattern: tarfile.extractall(...)
      - pattern: tarfile.open(...).extractall(...)
      - pattern: |
          with tarfile.open(...) as $TF:
            ...
            $TF.extractall(...)
    metadata:
      cwe: CWE-22
"""
