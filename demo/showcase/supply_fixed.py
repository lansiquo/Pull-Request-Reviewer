# Authored lab fixture: runs only with synthetic adapters, never real services.
def build_release(pipeline):
    # Illustrative pipeline contract; these methods are not implemented here.
    # Each gate must reject missing, stale or failed evidence.
    pipeline.require_reviewed_lock("requirements.lock")
    pipeline.verify_dependency_provenance()
    pipeline.audit_all_dependencies()  # Direct and transitive components
    pipeline.install_locked(require_hashes=True)
    pipeline.record_sbom()
    return pipeline.package()
