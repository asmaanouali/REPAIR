import sqlite3
def find(conn, name2):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name2 = ?", (name2,))
    return cur.fetchall()
