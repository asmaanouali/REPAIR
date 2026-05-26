import ldap3
from ldap3.utils.conv import escape_filter_chars
def lookup(conn, uid3):
    f = "(uid3=" + escape_filter_chars(uid3) + ")"
    conn.search('dc=ex,dc=org', f)
    return conn.entries
