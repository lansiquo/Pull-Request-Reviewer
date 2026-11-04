# Authored lab fixture: runs only with synthetic adapters, never real services.
def read_invoice(invoices, current_user, invoice_id):
    invoice = invoices.get(invoice_id)
    return invoice.to_dict()
