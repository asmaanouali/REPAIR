public class A {
  public java.sql.ResultSet run(java.sql.Connection c, String name2) throws Exception {
    java.sql.PreparedStatement ps = c.prepareStatement("SELECT id FROM users WHERE name2 = ?");
    ps.setString(1, name2);
    return ps.executeQuery();
  }
}
