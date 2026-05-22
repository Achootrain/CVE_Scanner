"""Mine version-detection rules for every active WP plugin in slugs.json.

For each active plugin:
  1. Query SVN tags listing on plugins.svn.wordpress.org for available tags.
  2. Pick primary = newest stable tag (filter out beta/rc/alpha).
  3. Pick cross = next 3 older stable tags.
  4. If no tags exist (plugin author commits to trunk only), download
     trunk-as-current zip with no cross validation -- rules still emit
     against primary, just less validated.
  5. Generate plugins/<slug>/config.yaml on the fly.
  6. Invoke mine_paths.py for that plugin.

Output:
  plugins/<slug>/config.yaml          -- generated config
  plugins/<slug>/version_rules.json   -- per-plugin rules
  plugins/_summary.json               -- aggregate of all plugin rules

Plugins whose status in slugs.json is "closed" are skipped (their SVN may
be partially wiped after a security closure -- best handled as a separate
historical-archive workflow).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
SLUGS_FILE = HERE / "fontawesome" / "slugs.json"
PLUGINS_DIR = HERE / "plugins"
MINER = HERE / "mine_paths.py"

SVN_TAGS = "https://plugins.svn.wordpress.org/{slug}/tags/"
API_INFO = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}"
ARCHIVE_TAGGED = "https://downloads.wordpress.org/plugin/{slug}.{tag}.zip"
ARCHIVE_TRUNK = "https://downloads.wordpress.org/plugin/{slug}.zip"
RAW_TAG = "https://plugins.svn.wordpress.org/{slug}/tags/{tag}/{path}"

INCLUDE_PATHS = [
    "readme.txt",
    "*.php",
    "**/*.php",
    "block.json",
    "package.json",
]

REGEX_BANK = [
    {"label": "wp plugin readme: Stable tag: X.Y.Z",
     "pattern": r"(?im)^Stable\s*tag\s*:\s*([0-9][\w.\-]*)"},
    {"label": "php header: Version: X.Y.Z",
     "pattern": r"(?im)^\s*\*?\s*Version\s*:\s*([0-9][\w.\-]*)"},
    {"label": 'json: "version": "X.Y.Z"',
     "pattern": r'"version"\s*:\s*"([0-9][^"]*)"'},
    {"label": 'php define: PLUGIN_VERSION-style constant',
     "pattern": r"""define\s*\(\s*['"][A-Z][A-Z0-9_]*VERSION['"]\s*,\s*['"]([0-9][\w.\-]*)['"]"""},
]


def curl(url: str, timeout: int = 15) -> bytes | None:
    r = subprocess.run(["curl", "-sSL", "--max-time", str(timeout), "--globoff", url],
                       capture_output=True)
    if r.returncode != 0:
        return None
    return r.stdout


_VER_RE = re.compile(r"^[0-9][\w.\-]*$")
_PRERELEASE = re.compile(r"(?i)(beta|rc|alpha|dev|nightly)")


def _version_key(t: str) -> tuple:
    parts = re.split(r"[.\-_]", t.lstrip("v"))
    out = []
    for p in parts:
        if p.isdigit():
            out.append((0, int(p)))
        else:
            out.append((1, p))
    return tuple(out)


def fetch_tags(slug: str) -> list[str]:
    body = curl(SVN_TAGS.format(slug=slug))
    if body is None:
        return []
    text = body.decode("utf-8", errors="replace")
    tags = re.findall(r'<li><a href="([^"/]+)/?">', text)
    tags = [t for t in tags if t != ".." and _VER_RE.match(t) and not _PRERELEASE.search(t)]
    return sorted(tags, key=_version_key, reverse=True)


def fetch_current_version(slug: str) -> str | None:
    """Query wp.org plugin API for the slug's currently published version."""
    body = curl(API_INFO.format(slug=slug))
    if body is None:
        return None
    try:
        d = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return d.get("version")


def write_config(slug: str, tags: list[str]) -> Path:
    outdir = PLUGINS_DIR / slug
    outdir.mkdir(parents=True, exist_ok=True)
    if tags:
        cfg = {
            "slug": slug,
            "archive_url": ARCHIVE_TAGGED,
            "raw_url": RAW_TAG,
            "primary": tags[0],
            "cross": tags[1:4],
            "include_paths": INCLUDE_PATHS,
            "regex_bank": REGEX_BANK,
        }
    else:
        # Trunk-only: query API for the actual current version so the literal
        # scan finds something, then skip cross-validate (no tags = no cross).
        current = fetch_current_version(slug) or "0.0.0"
        cfg = {
            "slug": slug,
            "archive_url": ARCHIVE_TRUNK,
            "raw_url": RAW_TAG,
            "primary": current,
            "cross": [],
            "include_paths": INCLUDE_PATHS,
            "regex_bank": REGEX_BANK,
        }
    path = outdir / "config.yaml"
    path.write_text(yaml.dump(cfg, sort_keys=False), encoding="utf-8")
    return path


def run_miner(config_path: Path) -> tuple[int, int]:
    """Return (exit_code, rule_count)."""
    r = subprocess.run([sys.executable, str(MINER), "--config", str(config_path)],
                       capture_output=True)
    rules_file = config_path.parent / "version_rules.json"
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", errors="replace"))
        return r.returncode, 0
    if not rules_file.exists():
        return r.returncode, 0
    n = len(json.loads(rules_file.read_text(encoding="utf-8")).get("rules", []))
    return r.returncode, n


def main() -> int:
    slugs_doc = json.loads(SLUGS_FILE.read_text(encoding="utf-8"))
    active = [s for s in slugs_doc["slugs"] if s["status"] == "active"]
    print(f"active plugins: {len(active)}", file=sys.stderr)

    summary = []
    for s in active:
        slug = s["slug"]
        print(f"\n=== {slug} ===", file=sys.stderr)
        tags = fetch_tags(slug)
        if tags:
            print(f"    found {len(tags)} tags; primary={tags[0]} cross={tags[1:4]}", file=sys.stderr)
        else:
            print(f"    no SVN tags (trunk-only plugin); cross-validation skipped", file=sys.stderr)
        config_path = write_config(slug, tags)
        code, n_rules = run_miner(config_path)
        status = "OK" if code == 0 else f"FAIL (exit {code})"
        print(f"    {status}: {n_rules} rules", file=sys.stderr)
        summary.append({
            "slug": slug,
            "product": s["product"],
            "primary": tags[0] if tags else "current",
            "cross": tags[1:4] if tags else [],
            "tagged": bool(tags),
            "rule_count": n_rules,
            "exit_code": code,
        })

    summary_path = PLUGINS_DIR / "_summary.json"
    summary_path.write_text(json.dumps({"plugins": summary}, indent=2), encoding="utf-8")
    print(f"\n[wrote] {summary_path}", file=sys.stderr)
    total = sum(p["rule_count"] for p in summary)
    succeeded = sum(1 for p in summary if p["exit_code"] == 0)
    print(f"Aggregate: {succeeded}/{len(summary)} plugins mined OK; {total} total rules", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
