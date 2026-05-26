import ldap3
from ldap3.utils.conv import escape_filter_chars
def lookup(conn, uid2):
    f = "(uid2=" + escape_filter_chars(uid2) + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
