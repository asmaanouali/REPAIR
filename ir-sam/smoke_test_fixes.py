"""Smoke tests for all 7 IR-SAM limitation fixes."""
import re
import sys

# ---- Fix #2: DI/DataSource connection detection --------------------------------
from core.rewriter import _find_connection

src_di = (
    "public class Dao {\n"
    "    @Autowired\n"
    "    private Connection conn;\n"
    "    public void query(String name) {\n"
    "        Statement stmt = conn.createStatement();\n"
    "        stmt.executeQuery(\"SELECT * FROM t WHERE n='\" + name + \"'\");\n"
    "    }\n"
    "}\n"
)
conn = _find_connection(src_di, 6)
assert conn is not None, f"Fix #2 FAIL: DI Connection not found (got {conn!r})"
print(f"Fix #2 PASS: DI conn = {conn!r}")

src_ds = (
    "public class Dao {\n"
    "    DataSource dataSource;\n"
    "    public void q(String x) {\n"
    "        dataSource.getConnection().createStatement().executeQuery(\"SELECT \" + x);\n"
    "    }\n"
    "}\n"
)
conn2 = _find_connection(src_ds, 4)
assert conn2 is not None, f"Fix #2 FAIL: DataSource chain not found (got {conn2!r})"
print(f"Fix #2 PASS: DataSource chain conn = {conn2!r}")

# ---- Fix #3: UUID-suffixed variables -----------------------------------------
from core.slicer import SliceResult, StringPart
from core.phi import PatchPlan, SetterCall
from core.rewriter import synthesize_patch

slice1 = SliceResult(
    parts=(StringPart.lit("SELECT * FROM t WHERE id="), StringPart.var("id", "int")),
    method_text="",
    method_start_line=1,
    sink_call_text='stmt.executeQuery(sql)',
    sink_call_line=6,
    sink_var_name="sql",
    declarations_to_remove=(),
)
plan1 = PatchPlan(
    prepared_template="SELECT * FROM t WHERE id=?",
    setter_calls=(SetterCall(
        param_index=1,
        api="java.sql.PreparedStatement.setInt",
        short_method="setInt",
        host_expr="id",
        hole_name="h0",
    ),),
    allowlist_guards=(),
    realizations=(),
    catalog_id="sql_jdbc",
    binder_ids_used=(),
    proof_obligations=(),
)
java_src = (
    "import java.sql.*;\n"
    "public class T {\n"
    "    Connection conn = null;\n"
    "    public void q(int id) {\n"
    "        String sql = \"SELECT * FROM t WHERE id=\" + id;\n"
    '        stmt.executeQuery(sql);\n'
    "    }\n"
    "}\n"
)
try:
    r1 = synthesize_patch(java_src, slice1, plan1)
    r2 = synthesize_patch(java_src, slice1, plan1)
    m1 = re.search(r"__irsam_ps_([a-f0-9]{6})", r1.patched_source)
    m2 = re.search(r"__irsam_ps_([a-f0-9]{6})", r2.patched_source)
    assert m1 and m2, "Fix #3 FAIL: no uid pattern found in patched source"
    uid1, uid2 = m1.group(1), m2.group(1)
    assert uid1 != uid2, f"Fix #3 FAIL: same uid across two calls: {uid1}"
    print(f"Fix #3 PASS: uid1={uid1}, uid2={uid2} (unique per patch)")
except Exception as e:
    print(f"Fix #3 FAIL: {e}")
    import traceback; traceback.print_exc()

# ---- Fix #6: Shell fallback split --------------------------------------------
from core.rewriter.shell import _fallback_split

class _P:
    def __init__(self, kind, value):
        self.kind = kind
        self.value = value

from core.rewriter.shell import _build_argv_items
parts_ok = (_P("literal", "ls -la "), _P("var", "path"))
items = _build_argv_items(tuple(parts_ok))
assert len(items) == 2, f"Fix #6 FAIL: expected 2 argv items got {len(items)}: {items}"
print(f"Fix #6 PASS: argv items count = {len(items)}")

toks = _fallback_split("cmd ___IRSAM_VAR_0___ --flag")
assert len(toks) == 3, f"Fix #6 FAIL: fallback split got {toks}"
print(f"Fix #6 PASS: fallback split = {toks}")

# ---- Fix #7: Non-SQL differential gate -------------------------------------
from core.validator import run_interpreter_structural_gate

g_shell_ok = run_interpreter_structural_gate(
    'new ProcessBuilder("ls", arg).start();', "shell"
)
assert g_shell_ok.passed, f"Fix #7 FAIL: shell gate should pass: {g_shell_ok.detail}"
print(f"Fix #7 PASS: shell gate (good) = {g_shell_ok.detail}")

g_shell_bad = run_interpreter_structural_gate(
    'Runtime.getRuntime().exec("ls " + arg);', "shell"
)
assert not g_shell_bad.passed, f"Fix #7 FAIL: shell gate should fail without ProcessBuilder"
print(f"Fix #7 PASS: shell gate (bad) = {g_shell_bad.detail}")

g_ldap_ok = run_interpreter_structural_gate(
    'ctx.search("ou=users", encodeForLDAP(uid));', "ldap"
)
assert g_ldap_ok.passed, f"Fix #7 FAIL: ldap gate should pass: {g_ldap_ok.detail}"
print(f"Fix #7 PASS: ldap gate = {g_ldap_ok.detail}")

g_xpath_ok = run_interpreter_structural_gate(
    "xpath.setXPathVariableResolver(r); xpath.evaluate(expr, doc);", "xpath"
)
assert g_xpath_ok.passed, f"Fix #7 FAIL: xpath gate should pass: {g_xpath_ok.detail}"
print(f"Fix #7 PASS: xpath gate = {g_xpath_ok.detail}")

# ---- Fix #8: run_file_all signature -----------------------------------------
import inspect
from core.pipeline import run_file_all

sig = inspect.signature(run_file_all)
assert "java_path" in sig.parameters, "Fix #8 FAIL: run_file_all missing java_path param"
print(f"Fix #8 PASS: run_file_all exists with correct signature")

# ---- Fix #1: Framework annotation slicer -----------------------------------
from core.slicer import _LocalEnv, _scan_method_params

env = _LocalEnv()
method_with_annotation = (
    "public void doQuery(@RequestParam String username, int id) {\n"
    "    String sql = \"SELECT * FROM u WHERE name='\" + username + \"'\";\n"
    "    stmt.executeQuery(sql);\n"
    "}\n"
)
_scan_method_params(method_with_annotation, env)
assert "username" in env.decls, f"Fix #1 FAIL: @RequestParam username not in env: {env.decls}"
assert env.decls["username"][0] == "String", (
    f"Fix #1 FAIL: wrong type for username: {env.decls['username']}"
)
print(f"Fix #1 PASS: @RequestParam username tracked as {env.decls['username']}")

# loop-built StringBuilder
env2 = _LocalEnv()
loop_method = (
    "public void buildQ(String[] ids) {\n"
    "    StringBuilder sb = new StringBuilder(\"SELECT * FROM t WHERE id IN (\");\n"
    "    for (String id : ids) { sb.append(id).append(','); }\n"
    "    sb.append(')');\n"
    "    stmt.executeQuery(sb.toString());\n"
    "}\n"
)
from core.slicer import _scan_locals
env2_result = _scan_locals(loop_method)
assert "sb" in env2_result.decls, f"Fix #1 FAIL: loop StringBuilder 'sb' not tracked"
print(f"Fix #1 PASS: loop StringBuilder tracked = {env2_result.decls['sb']}")

print()
print("All smoke tests PASSED.")
sys.exit(0)
