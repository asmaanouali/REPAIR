function fetchUser(conn, name) {
  const sql = "SELECT id FROM users WHERE name = '" + name + "'";
  return conn.query(sql);
}
