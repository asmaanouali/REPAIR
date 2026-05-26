public class A {
  public java.sql.ResultSet run(java.sql.Connection c, String name3) throws Exception {
    java.sql.PreparedStatement ps = c.prepareStatement("SELECT id FROM users WHERE name3 = ?");
    ps.setString(1, name3);
    return ps.executeQuery();
  }
}
