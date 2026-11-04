# Authored lab fixture: runs only with synthetic adapters, never real services.
def denied_access(audit, request_id):
    # Contract: structured encoding, bounded fields, durable protected storage.
    # No password, token or raw request body belongs in this record.
    audit.record(event="access_denied", request_id=request_id)
    # Alert routing and response ownership must be configured and exercised.
    return {"status": 403}
