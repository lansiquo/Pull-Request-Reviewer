# Authored lab fixture: runs only with synthetic adapters, never real services.
def build_release(pipeline):
    pipeline.install("requirements.txt")  # Unlocked dependency ranges
    return pipeline.package()
