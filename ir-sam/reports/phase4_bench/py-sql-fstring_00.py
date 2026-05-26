import sqlite3
def find_product(conn: sqlite3.Connection, sku: str):
    cur = conn.cursor()
    cur.execute(f"SELECT id FROM products WHERE sku = '{sku}'")
    return cur.fetchone()
