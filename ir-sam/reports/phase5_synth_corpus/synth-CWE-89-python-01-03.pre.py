import sqlite3
def find(conn, name3):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name3 = '" + name3 + "'")
    return cur.fetchall()
