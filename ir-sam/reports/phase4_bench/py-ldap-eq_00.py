import ldap3
def find_user(conn: ldap3.Connection, uid: str):
    f = "(uid=" + uid + ")"
    conn.search('dc=example,dc=org', f)
    return conn.entries
