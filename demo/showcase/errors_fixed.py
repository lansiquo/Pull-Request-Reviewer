# Authored lab fixture: runs only with synthetic adapters, never real services.
def may_download(policy, user, document):
    try:
        return policy.allows(user, document)
    except TimeoutError:
        # Deny access while the policy service is unavailable.
        # The caller must return a safe error and record the outage.
        return False
