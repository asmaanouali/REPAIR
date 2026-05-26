import ldap3
def lookup(conn, uid1):
    f = "(uid1=" + uid1 + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
