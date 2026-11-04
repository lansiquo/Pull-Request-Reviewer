# Authored lab fixture: runs only with synthetic adapters, never real services.
def redeem_coupon(store, user, coupon):
    # Design contract: one redemption per authenticated customer and coupon.
    # The transaction and unique constraint must be enforced in the database.
    with store.transaction():
        if not store.insert_redemption_unique(user.id, coupon.id):
            raise ValueError("Coupon already redeemed")
        store.credit(user.id, coupon.value)
