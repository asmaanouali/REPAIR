import ldap3
from ldap3.utils.conv import escape_filter_chars
def lookup(conn, uid1):
    f = "(uid1=" + escape_filter_chars(uid1) + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
