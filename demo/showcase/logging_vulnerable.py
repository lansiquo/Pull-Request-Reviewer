# Authored lab fixture: runs only with synthetic adapters, never real services.
def denied_access(audit, request_id):
    # The denial is returned, but defenders cannot see repeated failures.
    return {"status": 403}
