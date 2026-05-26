function find(conn, name1) {
  return conn.query("SELECT id FROM users WHERE name1 = ?", [name1]);
}
