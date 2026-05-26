"""Property: ``structurally_sound`` is idempotent and monotone.

Idempotence: re-running the predicate on a triple that already
passed must still pass; on a triple that failed it must still fail
with the same set of reasons.

Monotonicity: removing a valid realization can only make soundness
worse (never better).
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings

from core.iam import HostRealization, structurally_sound
from tests.property.strategies import iams

pytestmark = pytest.mark.property


def _trivial_realizations(iam) -> list[HostRealization]:
    rs: list[HostRealization] = []
    for h in iam.holes:
        if h.ctx.value == "value":
            rs.append(HostRealization(h.name, "parameterized-api",
                                      "java.sql.PreparedStatement.setString"))
        elif h.ctx.value in ("identifier", "structural"):
            rs.append(HostRealization(h.name, "allowlist-lookup", None))
        else:
            rs.append(HostRealization(h.name, "literal-in-template", None))
    return rs


@given(iam=iams())
@settings(max_examples=200, deadline=None)
def test_structurally_sound_is_idempotent(iam) -> None:
    apis = {"java.sql.PreparedStatement.setString"}
    rs = _trivial_realizations(iam)
    ok1, reasons1 = structurally_sound(iam, rs, apis)
    ok2, reasons2 = structurally_sound(iam, rs, apis)
    assert ok1 == ok2
    assert sorted(reasons1) == sorted(reasons2)


@given(iam=iams())
@settings(max_examples=200, deadline=None)
def test_structurally_sound_is_monotone_under_removal(iam) -> None:
    if not iam.holes:
        return
    apis = {"java.sql.PreparedStatement.setString"}
    full = _trivial_realizations(iam)
    ok_full, _ = structurally_sound(iam, full, apis)
    # Drop one realization
    partial = full[:-1]
    ok_partial, reasons_partial = structurally_sound(iam, partial, apis)
    # Removing a realization can never *improve* soundness.
    if ok_full:
        # If full was sound, partial must either be sound (no hole touched it)
        # or carry a reason mentioning the missing hole name.
        if not ok_partial:
            missing_hole = full[-1].hole_name
            assert any(missing_hole in r for r in reasons_partial)
    else:
        assert not ok_partial
