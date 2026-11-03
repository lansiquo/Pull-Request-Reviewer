# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A05 Security Misconfiguration: debug mode on and listening on every interface."""
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
