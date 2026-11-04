"""Service-owned demonstration rules; not the production webhook ruleset."""
SHOWCASE_RULESET = r'''
rules:
  - id: demo-python-sql-string-concatenation
    languages: [python]
    severity: ERROR
    message: SQL query built with string concatenation; use bound parameters.
    pattern: $DB.execute($LEFT + $RIGHT)
    metadata:
      cwe: CWE-89
      owasp: A05:2025
  - id: demo-python-shell-command
    languages: [python]
    severity: ERROR
    message: Shell execution can interpret user text as commands; use a fixed executable and validated arguments.
    pattern: subprocess.run(..., shell=True, ...)
    metadata:
      cwe: CWE-78
      owasp: A05:2025
  - id: demo-python-unsafe-yaml
    languages: [python]
    severity: ERROR
    message: Unsafe YAML loading can construct Python objects; use safe_load and validate the expected data shape.
    pattern-either:
      - pattern: yaml.load(..., Loader=yaml.Loader, ...)
      - pattern: yaml.load(..., Loader=yaml.UnsafeLoader, ...)
      - pattern: yaml.unsafe_load(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2025
  - id: demo-python-disabled-tls-verification
    languages: [python]
    severity: ERROR
    message: TLS certificate verification is disabled; retain certificate and hostname validation.
    pattern-either:
      - pattern: requests.get(..., verify=False, ...)
      - pattern: requests.post(..., verify=False, ...)
      - pattern: requests.request(..., verify=False, ...)
    metadata:
      cwe: CWE-295
      owasp: A04:2025
  - id: demo-python-fastapi-debug
    languages: [python]
    severity: ERROR
    message: Debug responses can expose internal diagnostics; disable debug in deployed applications.
    pattern: fastapi.FastAPI(..., debug=True, ...)
    metadata:
      cwe: CWE-489
      owasp: A02:2025
'''
