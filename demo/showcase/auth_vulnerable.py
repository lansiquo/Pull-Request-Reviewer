# Authored lab fixture: runs only with synthetic adapters, never real services.
def finish_login(auth, sessions, session_id, credentials):
    user = auth.verify(credentials)
    # Reuses a session identifier that may be known before login.
    sessions.bind_user(session_id, user.id)
    return session_id
