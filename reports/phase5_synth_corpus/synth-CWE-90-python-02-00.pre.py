import ldap3
def lookup(conn, uid0):
    f = "(uid0=" + uid0 + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
