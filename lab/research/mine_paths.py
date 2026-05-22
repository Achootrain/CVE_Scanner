"""Generic version-detection rule miner.

Driven by a per-library YAML config. The pipeline is library-agnostic:

    A. Download a primary version's source zip from github via curl.
       Extract under <config_dir>/out/source/.
    B. Scan every text file (matching include_paths globs) for the literal
       primary-version string. Record (rel_path, sample_context_+-60_chars).
    C. For each candidate path, fetch the same path from each cross_version
       via raw.githubusercontent.com and confirm the corresponding version
       string appears in similar context.
    D. From stable paths (version found in >= 2 cross versions in addition
       to primary), distill a regex by matching the surrounding context
       against the library's regex_bank. Emit <config_dir>/version_rules.json.

Config schema:

    repo: <owner>/<name>           # github repo (no scheme)
    primary: "X.Y.Z"               # version we download in full
    cross: ["A.B.C", "D.E.F"]      # versions cross-validated via raw fetch
    include_paths:                 # PurePosixPath.match globs; one must hit
      - "css/*.css"
      - "js/*.js"
      - "package.json"
      - "**/_variables.scss"
    regex_bank:                    # ordered list; first regex that matches
      - label: "header banner"     #   the +-60 char context wins
        pattern: 'Font Awesome (?:Free|Pro)\\s+([0-9][\\w.\\-]*)'

Usage:
    python lab/research/mine_paths.py --config lab/research/fontawesome/config.yaml
    python lab/research/mine_paths.py --config lab/research/fontawesome/config.yaml \\
        --primary 8.0.0 --cross 7.2.0,6.7.2          # override versions
"""
from __future__ import annotations

import argparse
import fnmatch
import io
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

import yaml


DEFAULT_ARCHIVE_URL = "https://codeload.github.com/{repo}/zip/refs/tags/{tag}"
DEFAULT_RAW_URL = "https://raw.githubusercontent.com/{repo}/{tag}/{path}"
UA = "VersionMinerLab/0.1"

# Known structural keys in the YAML config -- everything else is treated as
# a free variable available for URL template substitution.
_STRUCT_KEYS = {"archive_url", "raw_url", "primary", "cross", "include_paths", "regex_bank",
                "secondary_techs", "plugin_url_prefix"}
MAX_FILE_BYTES = 2 * 1024 * 1024
CONTEXT = 60

TEXT_EXTS = {
    ".css", ".scss", ".sass", ".less", ".js", ".mjs", ".ts",
    ".json", ".md", ".txt", ".html", ".xml", ".svg", ".yaml", ".yml",
    ".php",
}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    primary: str
    cross: list[str]
    include_paths: list[str]
    regex_bank: list[dict]
    archive_url: str       # pre-substituted for free vars (still has {tag})
    raw_url: str           # pre-substituted for free vars (still has {tag}/{path})
    config_dir: Path
    label: str             # human label, derived from a free var or config dir
    secondary_techs: list[dict]   # [{slug, path_filter?}, ...] - regex_bank donors
    plugin_url_prefix: str | None # production-URL prefix for bundled paths

    @classmethod
    def load(cls, path: Path) -> "Config":
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for key in ("primary", "cross", "include_paths", "regex_bank"):
            if key not in data:
                raise SystemExit(f"{path}: missing required key '{key}'")
        # Free variables: anything not in STRUCT_KEYS becomes a URL-template var.
        # Common ones: 'repo' (github), 'slug' (wp plugin). Strings only.
        free_vars = {k: str(v) for k, v in data.items() if k not in _STRUCT_KEYS}
        # URL defaults assume a github repo unless overridden.
        archive_tpl = data.get("archive_url", DEFAULT_ARCHIVE_URL)
        raw_tpl = data.get("raw_url", DEFAULT_RAW_URL)
        # Pre-substitute free vars; {tag}/{path} stay as placeholders.
        archive = archive_tpl.format(tag="{tag}", path="{path}", **free_vars)
        raw = raw_tpl.format(tag="{tag}", path="{path}", **free_vars)
        # plugin_url_prefix: explicit override > WP-plugin default if slug set.
        url_prefix = data.get("plugin_url_prefix")
        if url_prefix is None and "slug" in free_vars:
            url_prefix = f"/wp-content/plugins/{free_vars['slug']}/"
        raw_sec = data.get("secondary_techs") or []
        if isinstance(raw_sec, str):
            raw_sec = [raw_sec]
        # Each entry: bare slug str, OR dict {slug, path_filter?}.
        secondary: list[dict] = []
        for entry in raw_sec:
            if isinstance(entry, str):
                secondary.append({"slug": entry, "path_filter": None})
            elif isinstance(entry, dict) and entry.get("slug"):
                secondary.append({
                    "slug": str(entry["slug"]),
                    "path_filter": entry.get("path_filter"),
                })
        return cls(
            primary=str(data["primary"]),
            cross=[str(v) for v in data["cross"]],
            include_paths=list(data["include_paths"]),
            regex_bank=list(data["regex_bank"]),
            archive_url=archive,
            raw_url=raw,
            config_dir=path.parent.resolve(),
            label=free_vars.get("slug") or free_vars.get("repo") or path.parent.name,
            secondary_techs=secondary,
            plugin_url_prefix=url_prefix,
        )


# ---------------------------------------------------------------------------
# Fetch + extract
# ---------------------------------------------------------------------------

def curl_bytes(url: str, dest: Path | None = None, timeout: int = 120) -> bytes | None:
    """Returns body on HTTP 200, None otherwise. Stderr on failure."""
    cmd = ["curl", "-sSL", "--max-time", str(timeout), "-A", UA, "-w", "\n__HTTP__:%{http_code}", url]
    if dest is not None:
        cmd += ["-o", str(dest)]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            return None
        # When -o is used, http code goes to stdout; body went to file.
        code_line = r.stdout.decode("ascii", errors="ignore").strip().rsplit("__HTTP__:", 1)[-1]
        if code_line != "200":
            return None
        return dest.read_bytes()
    r = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
    if r.returncode != 0:
        return None
    sep = b"\n__HTTP__:"
    if sep not in r.stdout:
        return None
    body, _, code = r.stdout.rpartition(sep)
    if code.decode("ascii", errors="ignore").strip() != "200":
        return None
    return body[:MAX_FILE_BYTES]


def _content_root(work_dir: Path) -> Path:
    """If the zip created a single top-level subdir, return that; else work_dir.

    GitHub archive zips wrap content in <repo>-<tag>/. WordPress plugin zips
    wrap content in <slug>/. Either way the actual file tree starts one level
    below where extractall landed.
    """
    children = [p for p in work_dir.iterdir() if not p.name.startswith(".")]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return work_dir


def download_source(cfg: Config) -> Path:
    src_dir = cfg.config_dir / "out" / "source"
    src_dir.mkdir(parents=True, exist_ok=True)
    leaf = re.sub(r"[^a-zA-Z0-9._-]", "_", cfg.label)
    work_dir = src_dir / f"{leaf}-{cfg.primary}"
    zip_path = src_dir / f"{leaf}-{cfg.primary}.zip"
    if work_dir.exists() and any(work_dir.iterdir()):
        print(f"[skip] {work_dir} already extracted", file=sys.stderr)
        return _content_root(work_dir)
    if not zip_path.exists() or zip_path.stat().st_size < 1024:
        url = cfg.archive_url.format(tag=cfg.primary)
        print(f"[get] {url}", file=sys.stderr)
        if curl_bytes(url, zip_path) is None:
            raise SystemExit(f"failed to download {url}")
    print(f"      {zip_path.stat().st_size/1024/1024:.1f} MiB", file=sys.stderr)
    work_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(work_dir)
    return _content_root(work_dir)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    relpath: str
    line_no: int
    context: str


def _glob_to_re(pat: str) -> re.Pattern[str]:
    """Convert a glob to a fully-anchored regex.

    Rules:
      - leading "**/" -> matches anywhere ('any depth prefix')
      - otherwise the pattern is anchored at the repo root
      - "*" matches anything except "/" (single path segment)
      - "**" matches any number of path segments
    """
    if pat.startswith("**/"):
        anchor_prefix = r"(?:.*/)?"
        rest = pat[3:]
    else:
        anchor_prefix = ""
        rest = pat
    parts: list[str] = []
    i = 0
    while i < len(rest):
        c = rest[i]
        if rest[i:i+2] == "**":
            parts.append(r".*")
            i += 2
        elif c == "*":
            parts.append(r"[^/]*")
            i += 1
        elif c == "?":
            parts.append(r"[^/]")
            i += 1
        else:
            parts.append(re.escape(c))
            i += 1
    return re.compile("^" + anchor_prefix + "".join(parts) + "$")


def matches_include(rel: str, patterns: list[str]) -> bool:
    return any(_glob_to_re(pat).match(rel) for pat in patterns)


def scan_for_version(root: Path, version: str, include_paths: list[str]) -> dict[str, list[Hit]]:
    needle = version.encode()
    by_path: dict[str, list[Hit]] = {}
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in TEXT_EXTS:
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        if not matches_include(rel, include_paths):
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if needle not in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
        offsets = [m.start() for m in re.finditer(re.escape(version), text)][:3]
        hits: list[Hit] = []
        for off in offsets:
            line_no = text.count("\n", 0, off) + 1
            start = max(0, off - CONTEXT)
            end = min(len(text), off + len(version) + CONTEXT)
            hits.append(Hit(relpath=rel, line_no=line_no, context=text[start:end].replace("\n", "\\n")))
        if hits:
            by_path[rel] = hits
    return by_path


# ---------------------------------------------------------------------------
# Cross-validate
# ---------------------------------------------------------------------------

def find_version_context(text: str, version: str) -> str | None:
    i = text.find(version)
    if i < 0:
        return None
    start = max(0, i - CONTEXT)
    end = min(len(text), i + len(version) + CONTEXT)
    return text[start:end].replace("\n", "\\n")


def cross_validate(cfg: Config, paths: list[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for path in paths:
        entry: dict[str, dict] = {"versions": {}}
        for tag in cfg.cross:
            url = cfg.raw_url.format(tag=tag, path=path)
            blob = curl_bytes(url, timeout=20)
            if blob is None:
                entry["versions"][tag] = {"found": False, "reason": "404 or fetch failed"}
                continue
            try:
                text = blob.decode("utf-8")
            except UnicodeDecodeError:
                text = blob.decode("utf-8", errors="replace")
            ctx = find_version_context(text, tag)
            if ctx:
                entry["versions"][tag] = {"found": True, "context": ctx}
            else:
                entry["versions"][tag] = {"found": False, "reason": "file exists, version string missing"}
        result[path] = entry
    return result


# ---------------------------------------------------------------------------
# Regex distillation
# ---------------------------------------------------------------------------

def best_regex_for_context(context: str, regex_bank: list[dict]) -> tuple[str, str] | None:
    # Stored contexts have literal '\n' (two chars) where actual newlines were,
    # so JSON display stays single-line. Restore real newlines so MULTILINE
    # anchors like '^Stable tag:' work against the sample.
    real = context.replace("\\n", "\n")
    for entry in regex_bank:
        try:
            compiled = re.compile(entry["pattern"])
        except re.error as e:
            print(f"[warn] bad regex {entry.get('label')!r}: {e}", file=sys.stderr)
            continue
        if compiled.search(real):
            return entry["pattern"], entry["label"]
    return None


# ---------------------------------------------------------------------------
# Secondary-tech mining (bundled-tech version extraction)
# ---------------------------------------------------------------------------
#
# A plugin often ships with another tech baked into its tree (e.g.
# `better-font-awesome` ships FA 4.7.0 at `vendor/.../font-awesome.min.css`).
# Mining the plugin's own version doesn't surface that. This pass uses the
# bundled tech's regex_bank to look for any version string the bundled tech
# leaks anywhere in the plugin source, and records a production URL template
# so the back-test can fetch the asset directly.

def _research_root() -> Path:
    return Path(__file__).resolve().parent


def _load_secondary_regex_bank(slug: str) -> list[dict]:
    """Look up a tech's regex_bank from lab/research/<slug>/config.yaml or
    lab/research/plugins/<slug>/config.yaml. Returns the regex_bank list."""
    root = _research_root()
    for candidate in (root / slug / "config.yaml",
                      root / "plugins" / slug / "config.yaml"):
        if candidate.exists():
            try:
                data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
            except Exception:
                return []
            return list(data.get("regex_bank") or [])
    return []


def mine_bundled_techs(source_root: Path, cfg: Config) -> list[dict]:
    """Scan plugin source for any secondary-tech version pattern.

    For each entry in `cfg.secondary_techs`, load that tech's regex_bank from
    its config.yaml, then apply every pattern to every text file in the
    plugin source. First match per file wins (mirrors primary mining).

    Returns list of bundled_tech_rules dicts.
    """
    if not cfg.secondary_techs:
        return []

    out: list[dict] = []
    for sec_entry in cfg.secondary_techs:
        sec_slug = sec_entry["slug"]
        path_filter_raw = sec_entry.get("path_filter")
        path_filter: re.Pattern[str] | None = None
        if path_filter_raw:
            try:
                path_filter = re.compile(path_filter_raw, re.I)
            except re.error as e:
                print(f"[warn] secondary {sec_slug}: bad path_filter {path_filter_raw!r}: {e}", file=sys.stderr)
        bank = _load_secondary_regex_bank(sec_slug)
        if not bank:
            print(f"[warn] secondary tech {sec_slug!r}: no regex_bank found", file=sys.stderr)
            continue
        compiled = []
        for entry in bank:
            try:
                compiled.append((re.compile(entry["pattern"]), entry.get("label", "")))
            except re.error as e:
                print(f"[warn] secondary {sec_slug}: bad regex {entry.get('label')!r}: {e}", file=sys.stderr)
                continue
        if not compiled:
            continue

        sec_hits = 0
        for p in source_root.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in TEXT_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                body = p.read_bytes()
            except OSError:
                continue
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                text = body.decode("utf-8", errors="replace")
            rel = str(p.relative_to(source_root)).replace("\\", "/")
            if path_filter is not None and not path_filter.search(rel):
                continue
            for compiled_re, label in compiled:
                m = compiled_re.search(text)
                if not m:
                    continue
                try:
                    version = m.group(1)
                except IndexError:
                    continue
                # Avoid false positives: skip if the captured version is
                # identical to the plugin's own primary version (likely
                # picked up the plugin header itself, not the bundled tech).
                if version == cfg.primary:
                    continue
                url_template = None
                if cfg.plugin_url_prefix:
                    url_template = cfg.plugin_url_prefix.rstrip("/") + "/" + rel
                out.append({
                    "bundled_tech": sec_slug,
                    "plugin_relative_path": "/" + rel,
                    "url_path_template": url_template,
                    "regex": compiled_re.pattern,
                    "regex_family": label,
                    "detected_version": version,
                })
                sec_hits += 1
                break  # first match per file wins
        print(f"[bundled] {sec_slug}: {sec_hits} bundled rule(s)", file=sys.stderr)

    # Dedup: same (bundled_tech, plugin_relative_path, regex) collapses.
    seen: set[tuple[str, str, str]] = set()
    deduped = []
    for r in out:
        key = (r["bundled_tech"], r["plugin_relative_path"], r["regex"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    return deduped


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--primary", help="override primary version")
    ap.add_argument("--cross", help="comma-separated override of cross versions")
    args = ap.parse_args(argv)

    cfg = Config.load(args.config)
    if args.primary:
        cfg.primary = args.primary
    if args.cross:
        cfg.cross = [v.strip() for v in args.cross.split(",") if v.strip()]

    print(f"[cfg] label={cfg.label} primary={cfg.primary} cross={cfg.cross}", file=sys.stderr)
    print(f"      archive_url={cfg.archive_url}", file=sys.stderr)
    print(f"      raw_url={cfg.raw_url}", file=sys.stderr)
    print(f"      include_paths={cfg.include_paths}", file=sys.stderr)

    out_dir = cfg.config_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    root = download_source(cfg)
    by_path = scan_for_version(root, cfg.primary, cfg.include_paths)
    total_hits = sum(len(hs) for hs in by_path.values())
    print(f"[scan] {cfg.primary}: {total_hits} hits across {len(by_path)} files", file=sys.stderr)

    raw_doc = {
        "primary_version": cfg.primary,
        "source": cfg.archive_url,
        "files_with_version": len(by_path),
        "total_hits": total_hits,
        "matches": [
            {"path": path, "hits": [{"line": h.line_no, "context": h.context} for h in hs]}
            for path, hs in sorted(by_path.items())
        ],
    }
    (out_dir / "path_matches.json").write_text(json.dumps(raw_doc, indent=2), encoding="utf-8")
    print(f"[wrote] {out_dir/'path_matches.json'}", file=sys.stderr)

    candidates = sorted(by_path)
    print(f"[cross] candidates: {len(candidates)}", file=sys.stderr)
    for p in candidates[:30]:
        print(f"        {p}", file=sys.stderr)
    if len(candidates) > 30:
        print(f"        ... and {len(candidates) - 30} more", file=sys.stderr)

    cross = cross_validate(cfg, candidates)
    (out_dir / "cross_validate.json").write_text(json.dumps(cross, indent=2), encoding="utf-8")

    rules: list[dict] = []
    for path, entry in cross.items():
        found_in = [v for v, info in entry["versions"].items() if info["found"]]
        # Confidence threshold:
        #   - if no cross was attempted (cross=[]), accept primary-only rules
        #   - if cross was attempted, require >=1 hit (proof the rule survives version drift)
        if cfg.cross and len(found_in) < 1:
            continue
        # Pick a representative context: prefer a cross hit, else fall back to v7 hit.
        sample = None
        for v in cfg.cross:
            if entry["versions"].get(v, {}).get("found"):
                sample = entry["versions"][v]["context"]
                break
        if sample is None:
            v7_hit = by_path.get(path, [None])[0]
            sample = v7_hit.context if v7_hit else ""
        choice = best_regex_for_context(sample, cfg.regex_bank)
        if not choice:
            continue
        regex_src, regex_label = choice
        v7_ctx = by_path.get(path, [None])[0]
        rules.append({
            "path": "/" + path,
            "regex": regex_src,
            "regex_family": regex_label,
            "validated_versions": [cfg.primary] + sorted(found_in, key=lambda v: tuple(int(x) for x in v.split(".") if x.isdigit())),
            "sample_context": {
                cfg.primary: v7_ctx.context if v7_ctx else None,
                **{v: entry["versions"][v]["context"] for v in cfg.cross if entry["versions"][v]["found"]},
            },
        })

    rules.sort(key=lambda r: r["path"])
    out_doc = {
        "generated_at": "2026-05-13",
        "source": cfg.archive_url,
        "primary_version": cfg.primary,
        "cross_versions": cfg.cross,
        "rule_count": len(rules),
        "rules": rules,
    }

    # Secondary-tech pass: scan the same source tree for any bundled-tech
    # version patterns declared by `secondary_techs:` in the config.
    bundled = mine_bundled_techs(root, cfg)
    if bundled:
        bundled.sort(key=lambda r: (r["bundled_tech"], r["plugin_relative_path"]))
        out_doc["bundled_tech_rules"] = bundled
        print(f"[bundled] total: {len(bundled)} rule(s) across {len(set(r['bundled_tech'] for r in bundled))} tech(s)", file=sys.stderr)

    target = cfg.config_dir / "version_rules.json"
    target.write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    print(f"[wrote] {target} ({len(rules)} rules{', ' + str(len(bundled)) + ' bundled' if bundled else ''})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
