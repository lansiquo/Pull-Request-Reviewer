# Authored lab fixture: runs only with synthetic adapters, never real services.
def may_download(policy, user, document):
    try:
        return policy.allows(user, document)
    except TimeoutError:
        return True  # An unavailable security control grants access.
