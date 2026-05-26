"""Phase-7 framework-binding tests.

These tests assert:
  1. Every framework YAML loads and validates as DSL v0.
  2. The dispatcher selects the correct binder catalog from realistic
     host-source snippets, including positive and negative cases.
  3. The fall-through path remains generic when no framework signal
     is present.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from core.framework import (
    FrameworkProfile,
    catalog_path_for,
    detect_framework,
)


BINDERS = Path(__file__).resolve().parents[1] / "binders"

FRAMEWORK_YAMLS = [
    "spring_jdbctemplate.yaml",
    "mybatis.yaml",
    "hibernate_hql.yaml",
    "jpa.yaml",
    "django_orm.yaml",
]


# --- shape/conformance tests -----------------------------------------

@pytest.mark.parametrize("name", FRAMEWORK_YAMLS)
def test_framework_yaml_loads_dsl_v0(name: str) -> None:
    data = yaml.safe_load((BINDERS / name).read_text(encoding="utf-8"))
    assert data["dsl_version"] == "0"
    cat = data["catalog"]
    assert "id" in cat and "version" in cat
    assert cat["applies_to"]["interpreter"] in {"sql"}
    assert cat["applies_to"]["host_language"] in {"java", "python"}
    assert "framework" in cat["applies_to"]
    assert isinstance(cat["binders"], list) and cat["binders"], \
        f"{name}: at least one binder required"
    for b in cat["binders"]:
        assert {"id", "pattern", "rewrite", "proof_obligation"} <= set(b)


# --- dispatcher positive cases ---------------------------------------

def _src(s: str) -> str:
    return textwrap.dedent(s).strip()


def test_detects_spring_jdbctemplate() -> None:
    src = _src("""
        import org.springframework.jdbc.core.JdbcTemplate;
        public class UserDao {
            @Autowired private JdbcTemplate jdbc;
            public void load(String n) {
                jdbc.queryForList("SELECT * FROM u WHERE name='" + n + "'");
            }
        }
    """)
    p = detect_framework(host_language="java", source=src)
    assert p.name == "spring-jdbctemplate"
    assert p.catalog_basename == "spring_jdbctemplate"
    assert p.evidence, "evidence patterns should record what fired"


def test_detects_mybatis_via_annotation() -> None:
    src = _src("""
        import org.apache.ibatis.annotations.Select;
        public interface UserMapper {
            @Select("SELECT * FROM u WHERE name = ${name}")
            User find(String name);
        }
    """)
    p = detect_framework(host_language="java", source=src)
    assert p.name == "mybatis"


def test_detects_hibernate() -> None:
    src = _src("""
        import org.hibernate.Session;
        public class R {
            void load(Session s, String n) {
                s.createQuery("FROM User WHERE name='" + n + "'").list();
            }
        }
    """)
    p = detect_framework(host_language="java", source=src)
    assert p.name == "hibernate-hql"


def test_detects_jpa_jakarta() -> None:
    src = _src("""
        import jakarta.persistence.EntityManager;
        public class R {
            @PersistenceContext private EntityManager em;
            void load(String n) {
                em.createQuery("SELECT u FROM User u WHERE u.name='"+n+"'");
            }
        }
    """)
    p = detect_framework(host_language="java", source=src)
    assert p.name == "jpa"


def test_detects_django_orm_extra_where() -> None:
    src = _src("""
        from django.db import models
        def search(qs, name):
            return qs.extra(where=["name = '" + name + "'"])
    """)
    p = detect_framework(host_language="python", source=src)
    assert p.name == "django-orm"


def test_detects_django_orm_raw_cursor() -> None:
    src = _src("""
        from django.db import connection
        def run(name):
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM u WHERE name='%s'" % name)
    """)
    p = detect_framework(host_language="python", source=src)
    assert p.name == "django-orm"


# --- dispatcher negative / fallback cases ----------------------------

def test_plain_jdbc_falls_through_to_generic_java() -> None:
    src = _src("""
        import java.sql.Connection;
        public class R {
            void load(Connection c, String n) throws Exception {
                c.createStatement().executeQuery(
                    "SELECT * FROM u WHERE name='" + n + "'");
            }
        }
    """)
    p = detect_framework(host_language="java", source=src)
    assert p.name == "generic"
    assert p.catalog_basename == "sql_jdbc"


def test_plain_python_dbapi_falls_through() -> None:
    src = _src("""
        import sqlite3
        def run(con, n):
            con.execute("SELECT * FROM u WHERE name='" + n + "'")
    """)
    p = detect_framework(host_language="python", source=src)
    assert p.name == "generic"
    assert p.catalog_basename == "sql_pydbapi"


# --- catalog path resolution -----------------------------------------

def test_catalog_path_resolves_for_each_framework() -> None:
    for name in (
        "spring-jdbctemplate", "mybatis", "hibernate-hql", "jpa",
        "django-orm",
    ):
        base = {
            "spring-jdbctemplate": "spring_jdbctemplate",
            "mybatis": "mybatis",
            "hibernate-hql": "hibernate_hql",
            "jpa": "jpa",
            "django-orm": "django_orm",
        }[name]
        prof = FrameworkProfile(
            name=name, catalog_basename=base,
            host_language="java" if name != "django-orm" else "python")
        path = catalog_path_for(prof)
        assert path.exists(), f"missing binder YAML: {path}"


def test_priority_spring_beats_jpa_when_both_imports_present() -> None:
    # Realistic real-world Spring Boot service that imports JPA as
    # well; we want JdbcTemplate to win because it is the more
    # specific anti-pattern signal.
    src = _src("""
        import jakarta.persistence.EntityManager;
        import org.springframework.jdbc.core.JdbcTemplate;
        public class HybridDao {
            @Autowired JdbcTemplate jdbc;
            @PersistenceContext EntityManager em;
            void load(String n) {
                jdbc.queryForList("SELECT * FROM u WHERE name='"+n+"'");
            }
        }
    """)
    p = detect_framework(host_language="java", source=src)
    assert p.name == "spring-jdbctemplate"
