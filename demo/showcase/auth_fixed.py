# Authored lab fixture: runs only with synthetic adapters, never real services.
def finish_login(auth, sessions, session_id, credentials):
    user = auth.verify(credentials)
    # Contract: invalidate the old ID and atomically issue a fresh random ID.
    # The session service, secure cookie delivery and expiry need validation.
    return sessions.rotate_and_bind(session_id, user.id)
