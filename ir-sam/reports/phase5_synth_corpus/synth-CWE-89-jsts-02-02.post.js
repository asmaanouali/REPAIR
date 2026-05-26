function find(conn, name2) {
  return conn.query("SELECT id FROM users WHERE name2 = ?", [name2]);
}
