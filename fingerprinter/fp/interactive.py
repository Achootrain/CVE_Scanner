"""Interactive menu shell for fp.

A small REPL that lets the user pick a workflow from a numbered menu and
fills in arguments via prompts with filesystem-aware defaults, instead of
typing the full ``python -m fp.cli scan https://... --cache cache.json
--wap-db wappalyzer.db --retire-db retirejs.db ...`` form.

Stdlib only -- ``input()`` -- so it works on the user's Windows 11 box
without extra dependencies. ASCII-only output (cp1252-safe).

Each handler ALWAYS prints the equivalent long-form CLI command before
dispatching, so the user can learn the non-interactive form by watching.

The menu functions don't dispatch the heavy machinery themselves: they
build an ``argparse.Namespace`` and call the same ``_cmd_*`` functions
the non-interactive CLI uses, so behaviour stays in lockstep.
"""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path
from typing import Any, Callable, Iterable


# ---------------------------------------------------------------------------
# Prompt helpers (testable in isolation)
# ---------------------------------------------------------------------------


def _read_line(prompt: str, *, stdin=None) -> str:
    """Read one line from stdin. Wraps ``input()`` so tests can monkeypatch
    via ``builtins.input`` without caring about EOF semantics."""
    if stdin is None:
        return input(prompt)
    line = stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip("\n")


def prompt_text(
    label: str,
    *,
    default: str | None = None,
    required: bool = False,
    stdin=None,
) -> str:
    """Ask for a string. If ``required`` and no input + no default, re-asks.
    Empty input falls through to ``default`` when provided."""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        raw = _read_line(f"{label}{suffix}: ", stdin=stdin).strip()
        if raw:
            return raw
        if default is not None:
            return default
        if not required:
            return ""
        print("  (required)")


def prompt_yes_no(
    label: str,
    *,
    default: bool = True,
    stdin=None,
) -> bool:
    """Y/n style prompt. Empty input -> default."""
    hint = "Y/n" if default else "y/N"
    while True:
        raw = _read_line(f"{label} [{hint}]: ", stdin=stdin).strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  (please answer y or n)")


def prompt_path(
    label: str,
    *,
    default: str | None = None,
    must_exist: bool = False,
    stdin=None,
) -> str:
    """Prompt for a path; optionally re-ask until the path exists."""
    while True:
        raw = prompt_text(label, default=default, required=must_exist, stdin=stdin)
        if not raw:
            return raw
        if must_exist and not Path(raw).exists():
            print(f"  (path not found: {raw})")
            continue
        return raw


def prompt_choice(
    label: str,
    choices: list[tuple[str, str]],
    *,
    default_key: str | None = None,
    stdin=None,
) -> str:
    """Numbered menu prompt. ``choices`` is ``[(key, description), ...]``.

    Returns the chosen key. The user can type the index (1-based) or the
    key itself. Letter keys (e.g. 'q' for quit) are honoured.
    """
    print(f"\n{label}")
    keys = [k for k, _ in choices]
    for i, (key, desc) in enumerate(choices, start=1):
        marker = " *" if key == default_key else "  "
        print(f"  {i:2d}.{marker}{key:<20s}  {desc}")
    suffix = f" [{default_key}]" if default_key else ""
    while True:
        raw = _read_line(f"Choice{suffix}: ", stdin=stdin).strip().lower()
        if not raw and default_key:
            return default_key
        if raw in keys:
            return raw
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(choices):
                return keys[idx - 1]
        print(f"  (enter a number 1-{len(choices)} or one of: {', '.join(keys)})")


# ---------------------------------------------------------------------------
# Filesystem-aware defaults
# ---------------------------------------------------------------------------


def _default_if_exists(*candidates: str) -> str | None:
    """Return the first candidate path that exists, or None."""
    for c in candidates:
        if Path(c).exists():
            return c
    return None


# ---------------------------------------------------------------------------
# Echo + dispatch
# ---------------------------------------------------------------------------


def _echo_command(parts: list[str]) -> None:
    """Print the equivalent long-form CLI command, properly quoted."""
    rendered = " ".join(shlex.quote(p) for p in parts)
    print(f"\n  $ python -m fp.cli {rendered}\n")


# ---------------------------------------------------------------------------
# Per-command builders. Each returns (Namespace, [argv-style hint parts]).
# ---------------------------------------------------------------------------


def build_scan_args(stdin=None) -> tuple[argparse.Namespace, list[str]]:
    url = prompt_text("Target URL", required=True, stdin=stdin)
    cache_default = _default_if_exists("cache.json")
    cache = prompt_path(
        "Path to cache.json (blank to build from DB)",
        default=cache_default,
        stdin=stdin,
    )
    db = ""
    if not cache:
        db = prompt_path(
            "Path to fingerprints.db",
            default=_default_if_exists("fingerprints.db"),
            must_exist=True,
            stdin=stdin,
        )
    wap_db = prompt_path(
        "Path to wappalyzer.db (blank to skip)",
        default=_default_if_exists("wappalyzer.db"),
        stdin=stdin,
    )
    retire_db = prompt_path(
        "Path to retirejs.db (blank to skip)",
        default=_default_if_exists("retirejs.db"),
        stdin=stdin,
    )
    backend_probe = prompt_yes_no(
        "Run backend leak probes (Phase 5b)?", default=False, stdin=stdin,
    )
    expand = prompt_yes_no(
        "Expand subdomains via crt.sh?", default=False, stdin=stdin,
    )
    as_json = prompt_yes_no("Output as JSON?", default=False, stdin=stdin)

    ns = argparse.Namespace(
        targets=[url],
        cache=cache or None,
        db=db or None,
        wap_db=wap_db or None,
        retire_db=retire_db or None,
        backend_probe=backend_probe,
        expand_subdomains=expand,
        json=as_json,
        concurrency=8,
        timeout=15,
        verify_ssl=True,
    )
    parts = ["scan", url]
    if cache:
        parts += ["--cache", cache]
    elif db:
        parts += ["--db", db]
    if wap_db:
        parts += ["--wap-db", wap_db]
    if retire_db:
        parts += ["--retire-db", retire_db]
    if backend_probe:
        parts.append("--backend-probe")
    if expand:
        parts.append("--expand-subdomains")
    if as_json:
        parts.append("--json")
    return ns, parts



def build_subdomains_args(stdin=None) -> tuple[argparse.Namespace, list[str]]:
    domains_raw = prompt_text(
        "Apex domains (comma-separated)", required=True, stdin=stdin,
    )
    domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
    as_json = prompt_yes_no("JSON output?", default=False, stdin=stdin)
    ns = argparse.Namespace(domains=domains, json=as_json)
    parts = ["subdomains", *domains]
    if as_json:
        parts.append("--json")
    return ns, parts


# ---------------------------------------------------------------------------
# Top-level menu
# ---------------------------------------------------------------------------

# (key, description, builder, cmd_attr_name).
# cmd_attr_name names the function on cli module to dispatch (resolved lazily
# so the import order in cli.py stays simple).
_MENU: tuple[tuple[str, str, Callable, str], ...] = (
    ("scan",            "Fingerprint a URL (passive)",
     build_scan_args, "_cmd_scan"),
    ("subdomains",      "Enumerate subdomains via crt.sh",
     build_subdomains_args, "_cmd_subdomains"),
    ("q",               "Quit", None, ""),
)


def run_shell(stdin=None) -> int:
    """Top-level menu loop. Returns 0 on clean exit."""
    print("=== fp interactive shell ===")
    print("(stdlib only; type the number or the key to pick a workflow)")
    from . import cli as cli_mod  # local to avoid import cycle at module load

    while True:
        try:
            key = prompt_choice(
                "Pick a task",
                [(k, desc) for k, desc, _, _ in _MENU],
                default_key="scan",
                stdin=stdin,
            )
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if key == "q":
            return 0

        entry = next(e for e in _MENU if e[0] == key)
        _, _, builder, cmd_attr = entry
        try:
            ns, parts = builder(stdin=stdin)
        except (EOFError, KeyboardInterrupt):
            print("\n  (cancelled)")
            continue
        _echo_command(parts)
        func = getattr(cli_mod, cmd_attr)
        try:
            rc = func(ns)
        except KeyboardInterrupt:
            print("\n  (interrupted)")
            continue
        except Exception as exc:
            print(f"  command failed: {exc}")
            continue
        print(f"\n  (exit code {rc})")
