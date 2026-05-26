"""Inter-procedural slicing tests (Phase 4)."""
from core.slicer.interproc import slice_with_interproc
from core.slicer import SliceResult


_SRC = """
public class C {
  public ResultSet run(java.sql.Statement st, String name) throws Exception {
    return st.executeQuery(build(name));
  }
  private String build(String n) {
    return "SELECT id FROM users WHERE name = '" + n + "'";
  }
}
"""

_SRC_SIDE_EFFECTS = """
public class C {
  public ResultSet run(java.sql.Statement st, String name) throws Exception {
    return st.executeQuery(build(name));
  }
  private String build(String n) {
    if (n == null) throw new RuntimeException();
    return "SELECT 1";
  }
}
"""


def test_interproc_inlines_pure_helper():
    sink = next(i + 1 for i, l in enumerate(_SRC.splitlines())
                if "executeQuery" in l)
    res = slice_with_interproc(_SRC, sink)
    assert isinstance(res, SliceResult)
    vp = [p for p in res.parts if p.kind == "var"]
    assert vp and vp[0].value == "name"


def test_interproc_abstains_on_side_effects():
    sink = next(i + 1 for i, l in enumerate(_SRC_SIDE_EFFECTS.splitlines())
                if "executeQuery" in l)
    res = slice_with_interproc(_SRC_SIDE_EFFECTS, sink)
    # base slicer also failed; we either return its abstention OR
    # interproc_unsupported -- in both cases NOT a SliceResult.
    assert not isinstance(res, SliceResult)
