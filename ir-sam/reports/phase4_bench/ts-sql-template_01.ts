function fetchUser(conn: any, name: string) {
  return conn.query(`SELECT id FROM users WHERE name = '${name}'`);
}
