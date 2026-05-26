"""``irsam`` command-line interface (Typer)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.pipeline import run_file

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="IR-SAM: Intent-Reconstructive Secure API Migration")

console = Console()


@app.command()
def scan(file: Path) -> None:
    """Stage A: print sink call sites detected in FILE."""
    from core.slicer import find_sink_calls
    src = file.read_text(encoding="utf-8")
    sinks = find_sink_calls(src)
    table = Table(title=f"Sinks in {file}", show_lines=False)
    table.add_column("Line"); table.add_column("Receiver"); table.add_column("API")
    for line, recv, api, _text in sinks:
        table.add_row(str(line), recv, api)
    console.print(table)


@app.command()
def plan(file: Path,
         catalog: Path | None = typer.Option(None, help="Binder catalog YAML")) -> None:
    """Stages A..E: produce a patch plan (without rewriting)."""
    out = run_file(file, catalog_path=catalog)
    if out.plan is None:
        console.print(f"[yellow]Abstain at stage {out.stage_reached}:[/yellow] "
                      f"{out.abstention_reason}")
        raise typer.Exit(code=1)
    console.print(f"[green]Plan ready[/green] (catalog={out.plan.catalog_id})")
    console.print(f"prepared: [bold]{out.plan.prepared_template}[/bold]")
    for s in out.plan.setter_calls:
        console.print(f"  -> {s.short_method}({s.param_index}, {s.host_expr})  "
                      f"[dim]{s.api}[/dim]")
    for g in out.plan.allowlist_guards:
        console.print(f"  guard {g.hole_name}: {g.allowlist_java_const}"
                      f".get({g.host_expr})")


@app.command()
def patch(file: Path,
          out: Path = typer.Option(..., help="Patched file output path"),
          diff: Path | None = typer.Option(None, help="Unified diff output path")
          ) -> None:
    """Stages A..F: write the patched Java source."""
    res = run_file(file)
    if res.patch is None:
        console.print(f"[red]No patch at stage {res.stage_reached}:[/red] "
                      f"{res.abstention_reason}")
        raise typer.Exit(code=1)
    out.write_text(res.patch.patched_source, encoding="utf-8")
    if diff is not None:
        diff.write_text(res.patch.unified_diff, encoding="utf-8")
    console.print(f"[green]wrote {out}[/green]")


@app.command()
def validate(file: Path) -> None:
    """Stages A..G: run the 5-gate validator on the patched file."""
    res = run_file(file)
    if res.gates is None:
        console.print(f"[yellow]Pipeline did not reach G "
                      f"(stage {res.stage_reached}): {res.abstention_reason}[/yellow]")
        raise typer.Exit(code=1)
    table = Table(title="Stage-G gates")
    table.add_column("Gate"); table.add_column("Pass"); table.add_column("Detail")
    for g in res.gates.gates:
        table.add_row(g.name, "[green]\u2713[/green]" if g.passed
                              else "[red]\u2717[/red]", g.detail[:80])
    console.print(table)
    raise typer.Exit(code=0 if res.gates.overall_passed else 2)


@app.command()
def pipeline(file: Path,
             json_out: Path | None = typer.Option(None, help="Write JSON report")) -> None:
    """Stages A..G: full end-to-end run."""
    res = run_file(file)
    report = {
        "file": res.file,
        "stage_reached": res.stage_reached,
        "patched": res.patched,
        "all_gates_passed": res.all_gates_passed,
        "abstention_reason": res.abstention_reason,
        "plan": {
            "prepared": res.plan.prepared_template,
            "setters": [{"i": s.param_index, "api": s.api, "expr": s.host_expr}
                        for s in res.plan.setter_calls],
            "binders": list(res.plan.binder_ids_used),
        } if res.plan else None,
        "gates": [{"name": g.name, "passed": g.passed, "detail": g.detail}
                  for g in (res.gates.gates if res.gates else ())],
    }
    if json_out is not None:
        json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    console.print_json(data=report)


if __name__ == "__main__":
    app()
