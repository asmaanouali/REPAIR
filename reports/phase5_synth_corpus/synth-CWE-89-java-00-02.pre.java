public class A {
  public java.sql.ResultSet run(java.sql.Statement st, String name2) throws Exception {
    return st.executeQuery("SELECT id FROM users WHERE name2 = '" + name2 + "'");
  }
}
