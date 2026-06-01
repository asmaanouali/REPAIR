public class A {
  public java.sql.ResultSet run(java.sql.Connection c, String name1) throws Exception {
    java.sql.PreparedStatement ps = c.prepareStatement("SELECT id FROM users WHERE name1 = ?");
    ps.setString(1, name1);
    return ps.executeQuery();
  }
}
