public class A {
  public java.sql.ResultSet run(java.sql.Statement st, String name0) throws Exception {
    return st.executeQuery("SELECT id FROM users WHERE name0 = '" + name0 + "'");
  }
}
