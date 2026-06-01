import sqlite3
def find(conn, name0):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name0 = '" + name0 + "'")
    return cur.fetchall()
