"""Synchronous quickfix endpoint: paste code -> get diff."""

from __future__ import annotations

from fastapi import APIRouter

from core.api import QuickfixOptions, run_quickfix

from ..deps import CurrentUser
from ..schemas import GateOut, PatchOut, QuickfixRequest, QuickfixResponse

router = APIRouter(prefix="/quickfix", tags=["quickfix"])


@router.post("", response_model=QuickfixResponse)
async def quickfix(body: QuickfixRequest, _user: CurrentUser) -> QuickfixResponse:
    res = run_quickfix(
        body.source,
        QuickfixOptions(language=body.language, allowlists=body.allowlists),
    )
    r = res.result
    return QuickfixResponse(
        request_id=res.request_id,
        language=res.language,
        elapsed_ms=res.elapsed_ms,
        result=PatchOut(
            file=r.file,
            stage_reached=r.stage_reached,
            patched=r.patched,
            all_gates_passed=r.all_gates_passed,
            abstention_reason=r.abstention_reason,
            unified_diff=r.unified_diff,
            patched_source=r.patched_source,
            prepared_template=r.prepared_template,
            binders_used=list(r.binders_used),
            gates=[GateOut(name=g.name, passed=g.passed, detail=g.detail)
                   for g in r.gates],
        ),
    )
