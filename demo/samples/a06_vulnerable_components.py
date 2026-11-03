# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A06 Vulnerable and Outdated Components: this is an SCA problem, not a code pattern.
The risk lives in requirements.txt (for example, an old PyYAML or Jinja2 pin),
so a code scanner sees nothing wrong here. See the SCA Remediation Lab."""
import yaml


def load_config(text):
    return yaml.safe_load(text)
