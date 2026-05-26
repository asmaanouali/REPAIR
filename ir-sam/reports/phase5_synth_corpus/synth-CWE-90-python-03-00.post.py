import ldap3
from ldap3.utils.conv import escape_filter_chars
def lookup(conn, uid0):
    f = "(uid0=" + escape_filter_chars(uid0) + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
