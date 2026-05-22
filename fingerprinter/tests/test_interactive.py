"""Tests for the interactive menu shell.

We feed canned stdin via ``io.StringIO`` rather than monkeypatching
``builtins.input`` so the prompt helpers can be tested without global state.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_PKG_PARENT = _HERE.parent
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from fp import interactive as ix  # noqa: E402
from fp import cli as cli_mod  # noqa: E402


def _stdin(*lines: str) -> io.StringIO:
    return io.StringIO("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# prompt_text
# ---------------------------------------------------------------------------


def test_prompt_text_returns_input():
    assert ix.prompt_text("name", stdin=_stdin("alice")) == "alice"


def test_prompt_text_uses_default_on_empty():
    assert ix.prompt_text("name", default="bob", stdin=_stdin("")) == "bob"


def test_prompt_text_required_reasks(capsys):
    # First two empty (no default), third real value
    assert ix.prompt_text(
        "name", required=True, stdin=_stdin("", "", "carol")
    ) == "carol"
    # Captured stderr/stdout includes the (required) hint
    captured = capsys.readouterr().out
    assert "(required)" in captured


def test_prompt_text_strips_whitespace():
    assert ix.prompt_text("x", stdin=_stdin("   alice  ")) == "alice"


# ---------------------------------------------------------------------------
# prompt_yes_no
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("answer,expected", [
    ("y", True), ("Y", True), ("yes", True),
    ("n", False), ("N", False), ("no", False),
])
def test_prompt_yes_no_parses(answer, expected):
    assert ix.prompt_yes_no("ok", stdin=_stdin(answer)) is expected


def test_prompt_yes_no_default_true_on_empty():
    assert ix.prompt_yes_no("ok", default=True, stdin=_stdin("")) is True


def test_prompt_yes_no_default_false_on_empty():
    assert ix.prompt_yes_no("ok", default=False, stdin=_stdin("")) is False


def test_prompt_yes_no_reasks_on_garbage(capsys):
    assert ix.prompt_yes_no("ok", stdin=_stdin("maybe", "y")) is True
    assert "answer y or n" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# prompt_path
# ---------------------------------------------------------------------------


def test_prompt_path_must_exist_reasks(tmp_path: Path, capsys):
    real = tmp_path / "session.json"
    real.write_text("{}", encoding="utf-8")
    fake = tmp_path / "missing.json"

    chosen = ix.prompt_path(
        "session",
        must_exist=True,
        stdin=_stdin(str(fake), str(real)),
    )
    assert chosen == str(real)
    assert "path not found" in capsys.readouterr().out


def test_prompt_path_optional_can_be_blank():
    assert ix.prompt_path("optional", stdin=_stdin("")) == ""


# ---------------------------------------------------------------------------
# prompt_choice
# ---------------------------------------------------------------------------


def test_prompt_choice_by_number():
    choices = [("a", "first"), ("b", "second"), ("c", "third")]
    assert ix.prompt_choice("pick", choices, stdin=_stdin("2")) == "b"


def test_prompt_choice_by_key():
    choices = [("a", "first"), ("b", "second")]
    assert ix.prompt_choice("pick", choices, stdin=_stdin("a")) == "a"


def test_prompt_choice_default_on_empty():
    choices = [("a", "first"), ("b", "second")]
    assert ix.prompt_choice(
        "pick", choices, default_key="b", stdin=_stdin("")
    ) == "b"


def test_prompt_choice_reasks_on_garbage(capsys):
    choices = [("a", "first"), ("b", "second")]
    assert ix.prompt_choice("pick", choices, stdin=_stdin("zzz", "1")) == "a"
    assert "enter a number" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Filesystem default
# ---------------------------------------------------------------------------


def test_default_if_exists_returns_first_match(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "second.json").write_text("{}", encoding="utf-8")
    assert ix._default_if_exists("first.json", "second.json") == "second.json"


def test_default_if_exists_returns_none(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert ix._default_if_exists("nope.json") is None


# ---------------------------------------------------------------------------
# Builders -- check they produce both Namespace + matching argv parts
# ---------------------------------------------------------------------------





# ---------------------------------------------------------------------------
# Top-level shell loop
# ---------------------------------------------------------------------------


def test_run_shell_quits_immediately():
    rc = ix.run_shell(stdin=_stdin("q"))
    assert rc == 0


def test_run_shell_quits_on_eof():
    rc = ix.run_shell(stdin=io.StringIO(""))
    assert rc == 0





# ---------------------------------------------------------------------------
# Interactive entry via cli.main()
# ---------------------------------------------------------------------------


def test_cli_no_args_drops_into_interactive(monkeypatch, capsys):
    """`python -m fp.cli` with no subcommand should drop into the shell."""
    monkeypatch.setattr("sys.stdin", _stdin("q"))
    # But run_shell uses _read_line(prompt) -> input() when stdin=None.
    # Patch input() instead so we don't depend on sys.stdin readline behavior.
    answers = iter(["q"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    rc = cli_mod.main([])
    assert rc == 0
    assert "fp interactive shell" in capsys.readouterr().out


def test_cli_interactive_subcommand(monkeypatch, capsys):
    answers = iter(["q"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    rc = cli_mod.main(["interactive"])
    assert rc == 0
    assert "fp interactive shell" in capsys.readouterr().out
