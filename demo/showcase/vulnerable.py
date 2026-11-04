# Trusted analysis sample. The demo never runs this query or connects to a database.
def find_customer(connection, customer_name):
    return connection.execute(
        "SELECT id, name FROM customers WHERE name = '" + customer_name + "'"
    ).fetchall()
