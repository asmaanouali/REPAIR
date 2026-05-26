"""Unit tests for the Phase 9A POSIX-shell argv parser (CWE-78)."""
from __future__ import annotations

import pytest

from core.iam import Cardinality, Hole, Literal, SemType, SyntCtx
from core.parsers.shell import (
    ShellAmbiguousIntent,
    ShellSyntaxError,
    parse_shell_argv,
)
from core.recon import ParameterizedTemplate, TemplateHole


def _tpl(text: str, n_holes: int = 1) -> ParameterizedTemplate:
    holes = tuple(
        TemplateHole(idx=i, host_expr=f"v{i}", sem="string")
        for i in range(n_holes)
    )
    return ParameterizedTemplate(text=text, holes=holes)


def test_argv_with_hole_at_end_lifts_clean():
    tpl = _tpl("convert -resize 100x100 <<H0>>")
    lift = parse_shell_argv(tpl)
    assert lift.sig.kind == "Argv"
    assert len(lift.sig.children) == 4
    assert isinstance(lift.sig.children[0], Literal)
    assert lift.sig.children[0].value == "convert"
    assert lift.sig.children[1].value == "-resize"
    assert lift.sig.children[2].value == "100x100"
    h = lift.sig.children[3]
    assert isinstance(h, Hole)
    assert h.ctx is SyntCtx.VALUE
    assert h.sem is SemType.STRING
    assert h.card is Cardinality.ONE


def test_argv_with_quoted_hole_is_accepted():
    tpl = _tpl('echo "<<H0>>"')
    lift = parse_shell_argv(tpl)
    assert len(lift.sig.children) == 2
    assert isinstance(lift.sig.children[1], Hole)


def test_argv_with_pipe_abstains():
    tpl = _tpl("cat /etc/passwd | grep <<H0>>")
    with pytest.raises(ShellAmbiguousIntent):
        parse_shell_argv(tpl)


def test_argv_with_redirection_abstains():
    tpl = _tpl("convert <<H0>> > /tmp/out.png")
    with pytest.raises(ShellAmbiguousIntent):
        parse_shell_argv(tpl)


def test_argv_with_command_substitution_abstains():
    tpl = _tpl("echo $(whoami) <<H0>>")
    with pytest.raises(ShellAmbiguousIntent):
        parse_shell_argv(tpl)


def test_argv_with_mixed_token_abstains():
    """A hole concatenated with a bare literal must abstain."""
    tpl = _tpl("convert -resize <<H0>>x200 out.png")
    with pytest.raises(ShellAmbiguousIntent):
        parse_shell_argv(tpl)


def test_argv_with_mixed_token_in_quotes_abstains():
    tpl = _tpl('convert "-resize <<H0>>x200" out.png')
    with pytest.raises(ShellAmbiguousIntent):
        parse_shell_argv(tpl)


def test_argv_unterminated_string_is_syntax_error():
    tpl = _tpl('echo "hello')
    with pytest.raises(ShellSyntaxError):
        parse_shell_argv(tpl)


def test_argv_two_holes_both_become_value_slots():
    tpl = _tpl("git diff <<H0>> <<H1>>", n_holes=2)
    lift = parse_shell_argv(tpl)
    assert lift.sig.kind == "Argv"
    assert len(lift.sig.children) == 4
    h_nodes = [c for c in lift.sig.children if isinstance(c, Hole)]
    assert len(h_nodes) == 2
    assert {h.name for h in h_nodes} == {"h0", "h1"}
