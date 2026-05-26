import sqlite3
def find(conn, name1):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name1 = '" + name1 + "'")
    return cur.fetchall()
