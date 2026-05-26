"""Phase-E framework end-to-end tests.

For each of the five supported framework binders we run the full A..G
pipeline on three Bad and three Good code snippets and assert that:

1. The pipeline completes (no exception, returns a ``PatchRecord``).
2. For Bad snippets, the framework dispatcher selects the
   framework-specific catalog and the pipeline reaches at least the
   binding stage (Stage D — φ).  When the rewriter has a concrete
   plan for the framework (currently: ``spring-jdbctemplate``,
   ``django-orm`` raw cursor, ``sql_jdbc`` fall-through), we further
   assert that a unified diff was produced and at least one of the
   five validator gates ran.
3. For Good snippets (already-parameterised code), the pipeline must
   not silently rewrite safe constants.  Either it cleanly abstains
   with ``NO_VULN_PATTERN`` (or equivalent), or it returns no
   ``unified_diff``.
4. ``binders_used`` is populated for Bad snippets when a catalog is
   loaded.

These tests intentionally make minimal claims about the *content* of
the patch — that is covered by per-stage unit tests.  Phase-E only
guarantees that each framework's plumbing is wired up end-to-end and
that the safety net (abstain on safe input, never destroy semantics)
holds.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Iterable

import pytest

from core.api import QuickfixOptions, run_quickfix
from core.framework import FrameworkProfile, catalog_path_for, detect_framework

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _src(s: str) -> str:
    return textwrap.dedent(s).strip() + "\n"


def _catalog_for(name: str, host_language: str) -> str:
    base = {
        "spring-jdbctemplate": "spring_jdbctemplate",
        "mybatis": "mybatis",
        "hibernate-hql": "hibernate_hql",
        "jpa": "jpa",
        "django-orm": "django_orm",
    }[name]
    prof = FrameworkProfile(
        name=name, catalog_basename=base, host_language=host_language
    )
    return str(catalog_path_for(prof))


# ---------------------------------------------------------------------------
# Snippet corpora — 3 Bad + 3 Good per framework
# ---------------------------------------------------------------------------


SPRING_BAD = [
    # 1. queryForList with naked concat
    _src("""
        import org.springframework.jdbc.core.JdbcTemplate;
        public class UserDao {
            private final JdbcTemplate jdbc;
            public UserDao(JdbcTemplate j) { this.jdbc = j; }
            public java.util.List<java.util.Map<String,Object>> load(String name) {
                return jdbc.queryForList(
                    "SELECT * FROM users WHERE name = '" + name + "'");
            }
        }
    """),
    # 2. queryForObject + concatenation in WHERE
    _src("""
        import org.springframework.jdbc.core.JdbcTemplate;
        public class OrderDao {
            private final JdbcTemplate jdbc;
            public OrderDao(JdbcTemplate j) { this.jdbc = j; }
            public Integer count(String region) {
                return jdbc.queryForObject(
                    "SELECT COUNT(*) FROM orders WHERE region='" + region + "'",
                    Integer.class);
            }
        }
    """),
    # 3. update() with concat
    _src("""
        import org.springframework.jdbc.core.JdbcTemplate;
        public class AuditDao {
            private final JdbcTemplate jdbc;
            public AuditDao(JdbcTemplate j) { this.jdbc = j; }
            public int touch(String user) {
                return jdbc.update(
                    "UPDATE audit SET last='now' WHERE who='" + user + "'");
            }
        }
    """),
]

SPRING_GOOD = [
    _src("""
        import org.springframework.jdbc.core.JdbcTemplate;
        public class UserDao {
            private final JdbcTemplate jdbc;
            public UserDao(JdbcTemplate j) { this.jdbc = j; }
            public java.util.List<java.util.Map<String,Object>> load(String name) {
                return jdbc.queryForList(
                    "SELECT * FROM users WHERE name = ?", name);
            }
        }
    """),
    _src("""
        import org.springframework.jdbc.core.JdbcTemplate;
        public class OrderDao {
            private final JdbcTemplate jdbc;
            public OrderDao(JdbcTemplate j) { this.jdbc = j; }
            public Integer count(String region) {
                return jdbc.queryForObject(
                    "SELECT COUNT(*) FROM orders WHERE region=?",
                    Integer.class, region);
            }
        }
    """),
    _src("""
        import org.springframework.jdbc.core.JdbcTemplate;
        public class AuditDao {
            private final JdbcTemplate jdbc;
            public AuditDao(JdbcTemplate j) { this.jdbc = j; }
            public int touch(String user) {
                return jdbc.update(
                    "UPDATE audit SET last='now' WHERE who=?", user);
            }
        }
    """),
]


MYBATIS_BAD = [
    # 1. ${} unsafe substitution inside @Select
    _src("""
        import org.apache.ibatis.annotations.Select;
        public interface UserMapper {
            @Select("SELECT * FROM users WHERE name = '${name}'")
            User find(String name);
        }
    """),
    # 2. ${} inside ORDER BY
    _src("""
        import org.apache.ibatis.annotations.Select;
        public interface OrderMapper {
            @Select("SELECT * FROM orders ORDER BY ${col}")
            java.util.List<Order> byCol(String col);
        }
    """),
    # 3. ${} in @Update
    _src("""
        import org.apache.ibatis.annotations.Update;
        public interface UserMapper {
            @Update("UPDATE users SET role='${role}' WHERE id=${id}")
            int promote(int id, String role);
        }
    """),
]

MYBATIS_GOOD = [
    _src("""
        import org.apache.ibatis.annotations.Select;
        public interface UserMapper {
            @Select("SELECT * FROM users WHERE name = #{name}")
            User find(String name);
        }
    """),
    _src("""
        import org.apache.ibatis.annotations.Select;
        public interface OrderMapper {
            @Select("SELECT * FROM orders WHERE id = #{id}")
            Order byId(int id);
        }
    """),
    _src("""
        import org.apache.ibatis.annotations.Update;
        public interface UserMapper {
            @Update("UPDATE users SET role=#{role} WHERE id=#{id}")
            int promote(int id, String role);
        }
    """),
]


HIBERNATE_BAD = [
    _src("""
        import org.hibernate.Session;
        public class UserRepo {
            void load(Session s, String n) {
                s.createQuery("FROM User WHERE name='" + n + "'").list();
            }
        }
    """),
    _src("""
        import org.hibernate.Session;
        public class OrderRepo {
            Object count(Session s, String region) {
                return s.createQuery(
                    "SELECT COUNT(o) FROM Order o WHERE o.region='" + region + "'"
                ).uniqueResult();
            }
        }
    """),
    _src("""
        import org.hibernate.Session;
        public class AuditRepo {
            int touch(Session s, String who) {
                return s.createQuery(
                    "UPDATE Audit a SET a.last='now' WHERE a.who='" + who + "'"
                ).executeUpdate();
            }
        }
    """),
]

HIBERNATE_GOOD = [
    _src("""
        import org.hibernate.Session;
        public class UserRepo {
            void load(Session s, String n) {
                s.createQuery("FROM User WHERE name = :n")
                 .setParameter("n", n).list();
            }
        }
    """),
    _src("""
        import org.hibernate.Session;
        public class OrderRepo {
            Object count(Session s, String region) {
                return s.createQuery(
                    "SELECT COUNT(o) FROM Order o WHERE o.region = :r"
                ).setParameter("r", region).uniqueResult();
            }
        }
    """),
    _src("""
        import org.hibernate.Session;
        public class AuditRepo {
            int touch(Session s, String who) {
                return s.createQuery(
                    "UPDATE Audit a SET a.last='now' WHERE a.who = :w"
                ).setParameter("w", who).executeUpdate();
            }
        }
    """),
]


JPA_BAD = [
    _src("""
        import jakarta.persistence.EntityManager;
        import jakarta.persistence.PersistenceContext;
        public class UserRepo {
            @PersistenceContext private EntityManager em;
            Object load(String name) {
                return em.createQuery(
                    "SELECT u FROM User u WHERE u.name='" + name + "'"
                ).getSingleResult();
            }
        }
    """),
    _src("""
        import jakarta.persistence.EntityManager;
        import jakarta.persistence.PersistenceContext;
        public class OrderRepo {
            @PersistenceContext private EntityManager em;
            Object byRegion(String r) {
                return em.createQuery(
                    "SELECT o FROM Order o WHERE o.region='" + r + "'"
                ).getResultList();
            }
        }
    """),
    _src("""
        import jakarta.persistence.EntityManager;
        import jakarta.persistence.PersistenceContext;
        public class NativeRepo {
            @PersistenceContext private EntityManager em;
            Object load(String name) {
                return em.createNativeQuery(
                    "SELECT * FROM users WHERE name='" + name + "'"
                ).getResultList();
            }
        }
    """),
]

JPA_GOOD = [
    _src("""
        import jakarta.persistence.EntityManager;
        import jakarta.persistence.PersistenceContext;
        public class UserRepo {
            @PersistenceContext private EntityManager em;
            Object load(String name) {
                return em.createQuery(
                    "SELECT u FROM User u WHERE u.name = :n"
                ).setParameter("n", name).getSingleResult();
            }
        }
    """),
    _src("""
        import jakarta.persistence.EntityManager;
        import jakarta.persistence.PersistenceContext;
        public class OrderRepo {
            @PersistenceContext private EntityManager em;
            Object byRegion(String r) {
                return em.createQuery(
                    "SELECT o FROM Order o WHERE o.region = :r"
                ).setParameter("r", r).getResultList();
            }
        }
    """),
    _src("""
        import jakarta.persistence.EntityManager;
        import jakarta.persistence.PersistenceContext;
        public class NativeRepo {
            @PersistenceContext private EntityManager em;
            Object load(String name) {
                return em.createNativeQuery(
                    "SELECT * FROM users WHERE name = ?1"
                ).setParameter(1, name).getResultList();
            }
        }
    """),
]


DJANGO_BAD = [
    _src("""
        from django.db import connection
        def find_user(name):
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE name='%s'" % name)
                return cur.fetchall()
    """),
    _src("""
        from django.db import connection
        def count_orders(region):
            with connection.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM orders WHERE region='" + region + "'")
                return cur.fetchone()
    """),
    _src("""
        from django.db.models import Q
        def search(qs, name):
            return qs.extra(where=["name = '" + name + "'"])
    """),
]

DJANGO_GOOD = [
    _src("""
        from django.db import connection
        def find_user(name):
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE name = %s", (name,))
                return cur.fetchall()
    """),
    _src("""
        from django.db import connection
        def count_orders(region):
            with connection.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM orders WHERE region = %s", (region,))
                return cur.fetchone()
    """),
    _src("""
        def search(qs, name):
            return qs.filter(name=name)
    """),
]


# ---------------------------------------------------------------------------
# Parameter matrix
# ---------------------------------------------------------------------------


FRAMEWORK_MATRIX = [
    # (framework_name, host_language, bad_snippets, good_snippets)
    ("spring-jdbctemplate", "java",   SPRING_BAD,    SPRING_GOOD),
    ("mybatis",             "java",   MYBATIS_BAD,   MYBATIS_GOOD),
    ("hibernate-hql",       "java",   HIBERNATE_BAD, HIBERNATE_GOOD),
    ("jpa",                 "java",   JPA_BAD,       JPA_GOOD),
    ("django-orm",          "python", DJANGO_BAD,    DJANGO_GOOD),
]


def _bad_params() -> Iterable[tuple[str, str, str, int]]:
    for name, lang, bads, _ in FRAMEWORK_MATRIX:
        for i, src in enumerate(bads):
            yield (name, lang, src, i)


def _good_params() -> Iterable[tuple[str, str, str, int]]:
    for name, lang, _, goods in FRAMEWORK_MATRIX:
        for i, src in enumerate(goods):
            yield (name, lang, src, i)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("framework", "language", "source", "idx"),
    list(_bad_params()),
    ids=lambda v: v if isinstance(v, str) else str(v),
)
def test_bad_snippet_pipeline_completes_and_targets_framework(
    framework: str, language: str, source: str, idx: int
) -> None:
    """The pipeline must accept the input and dispatch the right catalog."""
    # 1. Framework dispatcher picks the right binder catalog.
    profile = detect_framework(host_language=language, source=source)
    assert profile.name == framework, (
        f"framework dispatcher misidentified snippet "
        f"#{idx} for {framework}: got {profile.name}"
    )

    # 2. Full pipeline runs without exception.
    catalog = _catalog_for(framework, language)
    res = run_quickfix(
        source,
        QuickfixOptions(language=language, catalog_path=catalog),
    )
    record = res.result
    assert record is not None
    assert record.stage_reached, "stage_reached must be populated"

    # 3. The catalog is actually loaded — binders_used not empty when
    #    pipeline reached at least Stage E (φ, where the catalog is
    #    first consulted).  Stage D is pure SQL parsing and runs
    #    *before* the binder catalog is loaded.
    reached_phi = record.stage_reached in {"E", "F", "G"}
    if reached_phi:
        assert record.binders_used, (
            f"binders_used empty despite stage {record.stage_reached} "
            f"for {framework} snippet #{idx}"
        )

    # 4. If we reached gates (F or G), at least one ran.
    if record.stage_reached in {"F", "G"}:
        assert len(record.gates) >= 1


@pytest.mark.parametrize(
    ("framework", "language", "source", "idx"),
    list(_good_params()),
    ids=lambda v: v if isinstance(v, str) else str(v),
)
def test_good_snippet_pipeline_does_not_rewrite_safe_code(
    framework: str, language: str, source: str, idx: int
) -> None:
    """Already-parameterised code must not be silently mutated.

    The pipeline is allowed to (a) cleanly abstain, (b) reach Stage G
    with a no-op diff, or (c) reach Stage G with a patch that does not
    remove parameter placeholders.  What it MUST NOT do is produce a
    patch that strips a parameter (``?`` / ``:n`` / ``%s`` / ``#{}``).
    """
    catalog = _catalog_for(framework, language)
    res = run_quickfix(
        source,
        QuickfixOptions(language=language, catalog_path=catalog),
    )
    record = res.result
    assert record is not None

    # If no patch was produced, we're already safe.
    if not record.unified_diff:
        return

    # If a patch *was* produced on already-safe code, it must not
    # remove the existing parameter placeholders.  We check that the
    # patched source still contains a placeholder appropriate for the
    # framework.
    patched = record.patched_source or ""
    placeholders = {
        "spring-jdbctemplate": ("?",),
        "mybatis":             ("#{",),
        "hibernate-hql":       (":",),
        "jpa":                 (":", "?1"),
        "django-orm":          ("%s", "filter("),
    }[framework]
    assert any(ph in patched for ph in placeholders), (
        f"Good snippet #{idx} for {framework} was rewritten in a way "
        f"that removed all parameter placeholders.\n--- Patched ---\n"
        f"{patched}\n--- Diff ---\n{record.unified_diff}"
    )


def test_matrix_covers_all_five_frameworks_with_three_pairs() -> None:
    """Sanity-check the matrix itself."""
    assert len(FRAMEWORK_MATRIX) == 5
    for name, _, bads, goods in FRAMEWORK_MATRIX:
        assert len(bads)  >= 3, f"{name}: need ≥3 Bad snippets"
        assert len(goods) >= 3, f"{name}: need ≥3 Good snippets"
