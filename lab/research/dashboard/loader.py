"""Discover and load lab/research artifacts.

Walks `lab/research/` for any directory containing `version_rules.json`,
returns structured records: config (YAML), rules (JSON), plus aggregate
summary from `plugins/_summary.json` when present.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


RESEARCH_ROOT = Path(__file__).resolve().parent.parent  # lab/research/
PLUGINS_DIR = RESEARCH_ROOT / "plugins"
SUMMARY_FILE = PLUGINS_DIR / "_summary.json"


@dataclass
class Library:
    slug: str                       # directory name
    kind: str                       # "library" | "plugin"
    dir: Path
    config: dict[str, Any] = field(default_factory=dict)
    rules: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)   # row from _summary.json

    # Shortcuts ------------------------------------------------------------

    @property
    def name(self) -> str:
        return (
            self.summary.get("product")
            or self.config.get("product")
            or self.slug
        )

    @property
    def rule_count(self) -> int:
        return len(self.rules.get("rules", []) or [])

    @property
    def primary(self) -> str:
        return (
            self.rules.get("primary_version")
            or self.config.get("primary")
            or ""
        )

    @property
    def cross(self) -> list[str]:
        return (
            self.rules.get("cross_versions")
            or self.config.get("cross")
            or []
        )

    @property
    def tagged(self) -> bool | None:
        # _summary.json carries the SVN-tag status for plugins.
        if "tagged" in self.summary:
            return bool(self.summary["tagged"])
        return None

    @property
    def exit_code(self) -> int | None:
        return self.summary.get("exit_code")

    @property
    def bundled_tech_rules(self) -> list[dict[str, Any]]:
        """Bundled-tech rules: produced when a plugin is mined with
        `secondary_techs:` declared. Each entry pins a version of another
        lab tech (e.g. font-awesome 4.7.0) bundled inside this plugin at a
        specific URL path, so the back-test can probe that path directly."""
        return self.rules.get("bundled_tech_rules", []) or []

    @property
    def url_pattern_rules(self) -> list[dict[str, Any]]:
        """URL-pattern rules (applied to URL strings, no HTTP fetch).

        Optional companion to body rules - lab entries can declare patterns
        that extract a version from URLs already present in scan-record
        endpoints + evidence URLs (e.g., WP `?ver=X.Y.Z` query params or
        CDN paths like `font-awesome/X.Y.Z/`).
        """
        return self.rules.get("url_patterns", []) or []

    @property
    def rule_rows(self) -> list[dict[str, Any]]:
        out = []
        for r in self.rules.get("rules", []) or []:
            out.append({
                "path": r.get("path", ""),
                "regex_family": r.get("regex_family", ""),
                "regex": r.get("regex", ""),
                "validated_versions": ", ".join(r.get("validated_versions", []) or []),
                "n_validated": len(r.get("validated_versions", []) or []),
            })
        return out


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _read_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def load_summary() -> dict[str, dict]:
    """Return {slug: row} from plugins/_summary.json."""
    raw = _read_json(SUMMARY_FILE)
    out: dict[str, dict] = {}
    for row in raw.get("plugins", []) or []:
        slug = row.get("slug")
        if slug:
            out[slug] = row
    return out


def discover_libraries(root: Path = RESEARCH_ROOT) -> list[Library]:
    """Return one Library per directory that contains version_rules.json."""
    summary = load_summary()
    libs: list[Library] = []
    for rules_path in sorted(root.rglob("version_rules.json")):
        d = rules_path.parent
        # Skip the dashboard's own dir or hidden stuff just in case.
        if d.name.startswith("_") or d.name == "dashboard":
            continue
        slug = d.name
        kind = "plugin" if d.parent.name == "plugins" else "library"
        config_path = d / "config.yaml"
        libs.append(Library(
            slug=slug,
            kind=kind,
            dir=d,
            config=_read_yaml(config_path) if config_path.exists() else {},
            rules=_read_json(rules_path),
            summary=summary.get(slug, {}),
        ))
    return libs


# ---------------------------------------------------------------------------
# Aggregate stats
# ---------------------------------------------------------------------------

@dataclass
class LabStats:
    n_libraries: int = 0
    n_plugins: int = 0
    total_rules: int = 0
    libs_with_zero_rules: list[str] = field(default_factory=list)
    libs_untagged: list[str] = field(default_factory=list)
    libs_failed: list[tuple[str, int]] = field(default_factory=list)
    regex_family_counts: Counter = field(default_factory=Counter)
    path_ext_counts: Counter = field(default_factory=Counter)
    n_validated_counts: Counter = field(default_factory=Counter)


def compute_stats(libs: list[Library]) -> LabStats:
    s = LabStats()
    for lib in libs:
        if lib.kind == "library":
            s.n_libraries += 1
        else:
            s.n_plugins += 1
        n = lib.rule_count
        s.total_rules += n
        if n == 0:
            s.libs_with_zero_rules.append(lib.slug)
        if lib.tagged is False:
            s.libs_untagged.append(lib.slug)
        if lib.exit_code not in (None, 0):
            s.libs_failed.append((lib.slug, lib.exit_code))

        for r in lib.rules.get("rules", []) or []:
            fam = r.get("regex_family") or "(unknown)"
            s.regex_family_counts[fam] += 1
            path = r.get("path") or ""
            ext = Path(path).suffix.lower() or "(none)"
            s.path_ext_counts[ext] += 1
            s.n_validated_counts[len(r.get("validated_versions", []) or [])] += 1
    return s


# ---------------------------------------------------------------------------
# Fontawesome CVE-driven artifacts (special-case alongside the mined rules)
# ---------------------------------------------------------------------------

FA_DIR = RESEARCH_ROOT / "fontawesome"


def load_fa_cves() -> dict:
    return _read_json(FA_DIR / "cves.json")


def load_fa_rules() -> dict:
    return _read_json(FA_DIR / "rules.json")


def load_fa_slugs() -> dict:
    return _read_json(FA_DIR / "slugs.json")
