import sqlite3
def get_user_by_id(conn, uid: int):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %d" % uid)
    return cur.fetchone()
