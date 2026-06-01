public class A {
  public java.sql.ResultSet run(java.sql.Connection c, String name0) throws Exception {
    java.sql.PreparedStatement ps = c.prepareStatement("SELECT id FROM users WHERE name0 = ?");
    ps.setString(1, name0);
    return ps.executeQuery();
  }
}
