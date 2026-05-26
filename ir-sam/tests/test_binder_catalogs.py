"""Validate every YAML in ``binders/`` against the binder schema.

Each catalog must:
- load without error,
- declare at least one ``parameterizing_apis`` entry,
- pass the closure check (no rule references an API outside the set),
- have unique binder ``id`` values within the catalog,
- be discoverable by ``core.binder.loader.load_catalog``.

This is the production replacement for ad-hoc YAML round-trips: any
schema drift breaks CI immediately.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.binder.loader import BinderCatalog, load_catalog

pytestmark = pytest.mark.unit

BINDERS_DIR = Path(__file__).resolve().parent.parent / "binders"

def _yaml_files() -> list[Path]:
    return sorted(BINDERS_DIR.glob("*.yaml"))


def _params() -> list:
    return [pytest.param(p, id=p.name) for p in _yaml_files()]


@pytest.mark.parametrize("yaml_path", _params())
def test_catalog_loads_and_passes_closure(yaml_path: Path) -> None:
    catalog = load_catalog(yaml_path)
    assert isinstance(catalog, BinderCatalog)
    assert catalog.parameterizing_apis, (
        f"{yaml_path.name}: parameterizing_apis must be non-empty"
    )
    assert catalog.binders, f"{yaml_path.name}: catalog must define at least one binder"


@pytest.mark.parametrize("yaml_path", _params())
def test_catalog_has_unique_binder_ids(yaml_path: Path) -> None:
    catalog = load_catalog(yaml_path)
    ids = [b.id for b in catalog.binders]
    assert len(ids) == len(set(ids)), (
        f"{yaml_path.name}: duplicate binder ids: "
        f"{[i for i in ids if ids.count(i) > 1]}"
    )


@pytest.mark.parametrize("yaml_path", _params())
def test_catalog_proof_obligations_documented(yaml_path: Path) -> None:
    """Every binder must cite a proof obligation (Lemma N. ...).

    Empty strings or missing fields make the catalog unreviewable.
    """
    catalog = load_catalog(yaml_path)
    bad = [b.id for b in catalog.binders if not b.proof_obligation.strip()]
    assert not bad, (
        f"{yaml_path.name}: binders missing proof_obligation: {bad}"
    )


def test_all_catalogs_collected() -> None:
    """Guard against accidentally dropping a binder catalog from the suite."""
    files = _yaml_files()
    assert files, "no binder YAMLs discovered"
    expected = {
        "django_orm.yaml", "hibernate_hql.yaml", "jpa.yaml", "ldap.yaml",
        "mybatis.yaml", "spring_jdbctemplate.yaml", "sql_jdbc.yaml",
        "sql_pydbapi.yaml", "xpath.yaml",
    }
    assert expected.issubset({p.name for p in files}), (
        f"missing catalogs: {expected - {p.name for p in files}}"
    )
