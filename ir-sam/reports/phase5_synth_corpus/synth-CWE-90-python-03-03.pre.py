import ldap3
def lookup(conn, uid3):
    f = "(uid3=" + uid3 + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
