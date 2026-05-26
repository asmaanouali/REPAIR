"""Shared SARIF 2.1.0 helpers used by detector adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

SARIF_VERSION = "2.1.0"


def load_sarif(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != SARIF_VERSION:
        raise ValueError(
            f"Unsupported SARIF version {data.get('version')!r}; expected {SARIF_VERSION}"
        )
    return data


def iter_results(sarif: dict[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Yield (run, result) tuples across all runs."""
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            yield run, result


def rule_id_of(result: dict[str, Any]) -> str:
    return result.get("ruleId") or result.get("rule", {}).get("id", "<unknown>")


def primary_location(result: dict[str, Any]) -> dict[str, Any] | None:
    locs = result.get("locations") or []
    if not locs:
        return None
    return locs[0]


def physical_location(result: dict[str, Any]) -> tuple[str, int, int | None]:
    loc = primary_location(result) or {}
    physical = loc.get("physicalLocation", {})
    uri = physical.get("artifactLocation", {}).get("uri", "<unknown>")
    region = physical.get("region", {})
    return uri, int(region.get("startLine", 1)), region.get("endLine")


def cwe_tags(result: dict[str, Any], rule: dict[str, Any] | None) -> list[str]:
    """Extract CWE-### tags from result properties or the referenced rule."""
    tags: list[str] = []
    for src in (result, rule or {}):
        props = src.get("properties", {}) if src else {}
        for tag in props.get("tags", []):
            t = str(tag).upper()
            if t.startswith("CWE-"):
                tags.append(t)
        for cwe in props.get("cwe", []) if isinstance(props.get("cwe"), list) else []:
            tags.append(f"CWE-{str(cwe).removeprefix('CWE-').removeprefix('cwe-')}")
    # uniq, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
