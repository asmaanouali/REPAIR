function find(conn, name3) {
  return conn.query("SELECT id FROM users WHERE name3 = '" + name3 + "'");
}
