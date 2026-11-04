# Authored lab fixture: runs only with synthetic adapters, never real services.
def redeem_coupon(store, user, coupon):
    # No requirement limits how often a customer can redeem this coupon.
    store.credit(user.id, coupon.value)
