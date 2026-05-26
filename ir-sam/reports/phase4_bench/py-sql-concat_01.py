import sqlite3
def fetch_user(conn: sqlite3.Connection, name: str):
    cur = conn.cursor()
    sql = "SELECT id FROM users WHERE name = '" + name + "'"
    cur.execute(sql)
    return cur.fetchall()
