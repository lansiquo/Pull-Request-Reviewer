# WARNING: INTENTIONALLY VULNERABLE CODE. Demo sample for the PR Reviewer playground.
# Never import, run, or deploy this file. It exists only to be scanned.
"""A01 Broken Access Control: any logged-in user can read any invoice (IDOR)."""


def get_invoice(db, current_user, invoice_id):
    # Missing check that the invoice belongs to current_user
    return db.query("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
