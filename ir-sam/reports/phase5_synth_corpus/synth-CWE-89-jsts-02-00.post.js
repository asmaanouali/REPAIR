function find(conn, name0) {
  return conn.query("SELECT id FROM users WHERE name0 = ?", [name0]);
}
