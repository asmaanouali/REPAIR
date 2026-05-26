public class A {
  public java.sql.ResultSet run(java.sql.Statement st, String name1) throws Exception {
    return st.executeQuery("SELECT id FROM users WHERE name1 = '" + name1 + "'");
  }
}
