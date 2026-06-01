public class A {
  public java.sql.ResultSet run(java.sql.Statement st, String name3) throws Exception {
    return st.executeQuery("SELECT id FROM users WHERE name3 = '" + name3 + "'");
  }
}
