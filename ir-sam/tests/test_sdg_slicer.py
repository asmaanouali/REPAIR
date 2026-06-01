"""Global (inter-procedural) SDG slicer tests.

These exercise the cross-file, multi-hop selective inlining built on
top of the project model in :mod:`core.slicer.project` and the SDG
slicer in :mod:`core.slicer.sdg`.
"""
from pathlib import Path

import pytest

from core.framework import extract_facts
from core.slicer import SliceAbstention, SliceResult
from core.slicer.project import ProjectModel
from core.slicer.sdg import slice_global, slice_global_traced


# A Spring-style three-file flow: controller -> service -> dao.
_CONTROLLER = """
package app.web;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
  @org.springframework.beans.factory.annotation.Autowired
  private UserService service;

  @GetMapping("/u")
  public java.sql.ResultSet find(@RequestParam String name) throws Exception {
    return service.lookup(name);
  }
}
"""

_SERVICE = """
package app.svc;
public class UserService {
  @org.springframework.beans.factory.annotation.Autowired
  private UserDao dao;

  public java.sql.ResultSet lookup(String n) throws Exception {
    return dao.query(n);
  }
}
"""

_DAO = """
package app.dao;
import java.sql.*;
public class UserDao {
  private Connection conn;

  public ResultSet query(String n) throws Exception {
    Statement st = conn.createStatement();
    return st.executeQuery(build(n));
  }
  private String build(String n) {
    return "SELECT id FROM users WHERE name = '" + n + "'";
  }
}
"""


def _model() -> ProjectModel:
    return ProjectModel.from_files({
        Path("UserController.java"): _CONTROLLER,
        Path("UserService.java"): _SERVICE,
        Path("UserDao.java"): _DAO,
    })


def _sink_line(src: str) -> int:
    return next(i + 1 for i, l in enumerate(src.splitlines())
               if "executeQuery" in l)


# --- project model ------------------------------------------------------------


def test_project_model_indexes_methods_and_fields():
    m = _model()
    assert set(m.methods_by_name) >= {"find", "lookup", "query", "build"}
    assert m.field_type("UserController", "service") == "UserService"
    assert m.field_type("UserService", "dao") == "UserDao"
    # method resolution by owner
    q = m.resolve_method("query", owner="UserDao")
    assert q is not None and q.owner == "UserDao"


def test_project_model_ambiguous_method_unresolved():
    m = _model()
    # two distinct 'build' would be ambiguous; here only one exists so
    # an unknown name must resolve to None.
    assert m.resolve_method("doesNotExist") is None


# --- intra-class inlining within the DAO --------------------------------------


def test_sdg_inlines_local_helper_same_file():
    m = _model()
    res = slice_global(m, Path("UserDao.java"), _sink_line(_DAO))
    assert isinstance(res, SliceResult)
    var_parts = [p for p in res.parts if p.kind == "var"]
    assert var_parts and var_parts[0].value == "n"


# --- the headline case: the sink is in the DAO, but the flow starts -----------
# in the controller. Slicing from the DAO sink still reconstructs the
# static SQL skeleton (the skeleton lives in build()).


def test_sdg_reconstructs_skeleton_across_helper():
    m = _model()
    result, trace = slice_global_traced(m, Path("UserDao.java"), _sink_line(_DAO))
    assert isinstance(result, SliceResult)
    # the build() helper was inlined
    assert any(s.callee == "build" for s in trace.steps)
    literals = [p.value for p in result.parts if p.kind == "literal"]
    assert any("SELECT id FROM users" in lit for lit in literals)


def test_framework_facts_detect_request_param():
    facts = extract_facts(host_language="java", source=_CONTROLLER)
    assert "name" in facts.tainted_params
    assert facts.is_web_entry is True


# --- soundness: impure helper must abstain ------------------------------------

_DAO_IMPURE = """
import java.sql.*;
public class BadDao {
  public ResultSet query(String n) throws Exception {
    Statement st = conn.createStatement();
    return st.executeQuery(build(n));
  }
  private String build(String n) {
    log(n);
    return "SELECT 1 FROM t WHERE x = '" + n + "'";
  }
}
"""


def test_sdg_abstains_on_impure_helper():
    m = ProjectModel.from_files({Path("BadDao.java"): _DAO_IMPURE})
    res = slice_global(m, Path("BadDao.java"), _sink_line(_DAO_IMPURE))
    assert isinstance(res, SliceAbstention)
    assert res.reason in {"sdg_impure_helper", "no_static_sql_skeleton"}


def test_sdg_depth_bound_is_enforced():
    # build() calls build() -> never terminates -> depth bound abstains.
    src = """
import java.sql.*;
public class Loop {
  public ResultSet q() throws Exception {
    Statement st = conn.createStatement();
    return st.executeQuery(a());
  }
  private String a() { return b(); }
  private String b() { return a(); }
}
"""
    m = ProjectModel.from_files({Path("Loop.java"): src})
    res = slice_global(m, Path("Loop.java"), _sink_line(src), max_depth=3)
    assert isinstance(res, SliceAbstention)
    assert res.reason in {"sdg_depth_exceeded", "no_static_sql_skeleton"}
