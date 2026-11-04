# Authored lab fixture: runs only with synthetic adapters, never real services.
def read_invoice(invoices, current_user, invoice_id):
    invoice = invoices.get(invoice_id)
    if invoice is None or invoice.owner_id != current_user.id:
        raise PermissionError("Invoice unavailable")
    return invoice.to_dict()
