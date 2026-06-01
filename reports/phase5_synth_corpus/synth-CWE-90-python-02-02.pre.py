import ldap3
def lookup(conn, uid2):
    f = "(uid2=" + uid2 + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
