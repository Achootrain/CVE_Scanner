"""Deterministic candidate-signal discovery (CLAUDE.md §12 sandwich step 3).

Walks a tech's acquired source under ``lab/research/<tech>/out/source/<ref>/``
and emits a list of candidate signals. Each candidate is "a place in the
source where the version is disclosed" -- the drafter's job downstream is
to author a regex that captures it.

Three detectors ship in the MVP. Add more (filename uniqueness across
versions, webfont families, CSS class prefixes, kit JS, etc.) once the
existing techs need them. CLAUDE.md §2: do not invent detectors before
the workload demands them.

  - find_banners
      Greps the first 30 lines of .js/.css/.scss/.less for
      <tech_token> <version> co-occurrences. Catches the gulp-header /
      build-banner output that almost every JS library emits.

  - find_package_metadata
      Parses package.json / bower.json / component.json / composer.json
      for the ``version`` field. The most authoritative declared
      version, but rarely directly observable in the wild -- still
      useful for the drafter as ground truth.

  - find_inline_version_constants
      Greps .js / .scss / .less / .css for ``version: 'X.Y.Z'`` or
      ``$<name>-version: X.Y.Z`` (Sass) literals. Catches version
      constants that get inlined into the shipped bundle.

Output: ``lab/research/<tech>/candidates.json``, an array of candidate
objects each carrying a stable ``candidate_id`` (re-running discover is
idempotent), the exact ``version_observed`` literal, an evidence span,
and a ``task_for_drafter`` string the drafter can consume directly.

The discoverer NEVER emits a regex. It points at evidence; the drafter
writes the regex with that evidence cited.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
RESEARCH = REPO / "lab" / "research"

# SemVer shape we accept. We deliberately don't require the patch component
# because libraries sometimes ship "X.Y" (jQuery 3.6 etc.). Pre-release
# suffix (-rc.1, -beta) is allowed.
SEMVER = r"(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?)"

_BANNER_HEAD_LINES = 30
_MAX_FILE_BYTES = 256_000
_BANNER_SUFFIXES = (".js", ".ts", ".css", ".scss", ".less", ".sass")
_PACKAGE_FILE_NAMES = ("package.json", "bower.json", "component.json", "composer.json")
_CONST_SUFFIXES = (".js", ".ts", ".scss", ".less", ".sass", ".css")
_SKIP_DIR_NAMES = {".git", "node_modules", "vendor", "__pycache__", "test", "tests", "spec"}


# ---------------------------------------------------------------------------
# Tech-token derivation
# ---------------------------------------------------------------------------

def _tokens_from_slug(slug: str) -> list[str]:
    """Build the set of substrings we'll look for next to a SemVer.

    For ``font-awesome`` -> ['font-awesome', 'fontawesome', 'Font Awesome',
    'FontAwesome', 'font', 'awesome']. Order matters only for evidence
    display: more-specific first.
    """
    parts = [p for p in re.split(r"[-_./]+", slug) if p]
    out = [slug]
    if len(parts) > 1:
        out.append("".join(parts))           # 'fontawesome'
        out.append(" ".join(p.capitalize() for p in parts))  # 'Font Awesome'
        out.append("".join(p.capitalize() for p in parts))   # 'FontAwesome'
    # Single-word parts last (very loose; only useful for the wider grep)
    out.extend(p for p in parts if p not in out)
    # Dedup, preserve order
    seen: set[str] = set()
    dedup: list[str] = []
    for t in out:
        k = t.lower()
        if k in seen:
            continue
        seen.add(k)
        dedup.append(t)
    return dedup


def _semver_from_ref_dir(ref_dir: Path) -> str | None:
    """Extract a SemVer-shaped string from the release-dir name.

    ``FA-4.7.0`` -> ``4.7.0``. Used as a sanity anchor: we trust
    version_observed more when it matches the directory's encoded ref.
    """
    m = re.search(SEMVER, ref_dir.name)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Candidate type
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    candidate_id: str
    kind: str                  # 'banner' | 'package_metadata' | 'inline_version_const'
    channel: str               # human-readable: 'css body' | 'json file' | ...
    anchor: str                # tech-name token observed near the version
    version_observed: str
    evidence: dict             # {file_path, line_start, line_end, preview}
    task_for_drafter: str


def _candidate_id(tech: str, kind: str, file_path: str, line_start: int) -> str:
    safe_path = re.sub(r"[^A-Za-z0-9]+", "-", file_path).strip("-")
    return f"{tech}--{kind}--{safe_path}--L{line_start}"


def _make_evidence(file_path_rel: str, line_start: int, line_end: int,
                   preview: str) -> dict:
    return {
        "file_path": file_path_rel,
        "line_start": line_start,
        "line_end": line_end,
        "preview": preview[:300],
    }


# ---------------------------------------------------------------------------
# Detector 1: banners
# ---------------------------------------------------------------------------

def find_banners(tech: str, source_root: Path) -> list[Candidate]:
    tokens = _tokens_from_slug(tech)
    # Strong banner pattern: tech token within 64 chars of a SemVer.
    # We build a regex per token so the matched substring is precise.
    token_alt = "|".join(re.escape(t) for t in tokens[:4])  # top-4 tokens
    if not token_alt:
        return []
    rx_token_then_ver = re.compile(
        rf"(?P<anchor>{token_alt})[^\n]{{0,40}}?v?{SEMVER}",
        re.IGNORECASE,
    )
    rx_ver_then_token = re.compile(
        rf"v?{SEMVER}[^\n]{{0,40}}?(?P<anchor>{token_alt})",
        re.IGNORECASE,
    )
    out: list[Candidate] = []
    for path in _iter_files(source_root, _BANNER_SUFFIXES):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head_lines = [next(f, "") for _ in range(_BANNER_HEAD_LINES)]
        except OSError:
            continue
        head = "".join(head_lines)
        if not head:
            continue
        m = rx_token_then_ver.search(head) or rx_ver_then_token.search(head)
        if not m:
            continue
        # Find which line the match started on (approximate)
        line_no = head[:m.start()].count("\n") + 1
        # Preview = the line containing the match plus a few neighbours
        start = max(0, line_no - 1)
        end = min(len(head_lines), start + 5)
        preview = "".join(head_lines[start:end])
        rel = str(path.relative_to(REPO)).replace("\\", "/")
        anchor = m.group("anchor")
        version = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
        # The capture-group indexing above is fragile; use a named group instead.
        version_match = re.search(SEMVER, m.group(0))
        version = version_match.group(1) if version_match else "?"
        cand = Candidate(
            candidate_id=_candidate_id(tech, "banner", rel, line_no),
            kind="banner",
            channel="css body" if path.suffix in (".css", ".scss", ".less") else "js body",
            anchor=anchor,
            version_observed=version,
            evidence=_make_evidence(rel, line_no, min(line_no + 4, line_no + len(head_lines)), preview),
            task_for_drafter=(
                f"Draft a 'banner' rule (section='banner_rules', kind='banner') "
                f"that captures the version from the comment header of "
                f"{rel}. The literal observed in this release is shown in "
                f"the evidence preview -- generalise it so it captures any "
                f"version of the same form (do not hardcode {version}). "
                f"applies_to should match the file type "
                f"({'css body' if path.suffix in ('.css', '.scss', '.less') else 'js body'})."
            ),
        )
        out.append(cand)
    return out


# ---------------------------------------------------------------------------
# Detector 2: package metadata
# ---------------------------------------------------------------------------

def find_package_metadata(tech: str, source_root: Path) -> list[Candidate]:
    out: list[Candidate] = []
    for path in _iter_files(source_root, suffixes=None):
        if path.name not in _PACKAGE_FILE_NAMES:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        version = data.get("version") if isinstance(data, dict) else None
        if not isinstance(version, str) or not re.match(SEMVER + "$", version):
            continue
        # Find the line that holds "version"
        try:
            text = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            text = []
        line_no = next(
            (i + 1 for i, ln in enumerate(text) if '"version"' in ln),
            1,
        )
        preview = "\n".join(text[max(0, line_no - 2):line_no + 1])
        rel = str(path.relative_to(REPO)).replace("\\", "/")
        out.append(Candidate(
            candidate_id=_candidate_id(tech, "package_metadata", rel, line_no),
            kind="package_metadata",
            channel="json file",
            anchor=path.name,
            version_observed=version,
            evidence=_make_evidence(rel, line_no, line_no + 1, preview),
            task_for_drafter=(
                "Package metadata is rarely the consumer-side signal we "
                "fingerprint -- visitors don't see package.json. Use this "
                "candidate as ground-truth for the version, then look for "
                "a co-shipped consumer-side disclosure (banner, "
                "filename, inline constant). Skip this candidate if no "
                "consumer-side signal exists."
            ),
        ))
    return out


# ---------------------------------------------------------------------------
# Detector 3: inline version constants
# ---------------------------------------------------------------------------

_RX_INLINE_CONST = re.compile(
    r"""(?:^|[\s;,(])
        (?P<key>version|VERSION|fa-version|__VERSION__)
        \s*[:=]\s*
        ['"]?
        """ + SEMVER + r"""
        ['"]?
    """,
    re.VERBOSE,
)


def find_inline_version_constants(tech: str, source_root: Path) -> list[Candidate]:
    out: list[Candidate] = []
    for path in _iter_files(source_root, _CONST_SUFFIXES):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > _MAX_FILE_BYTES:
            continue
        for m in _RX_INLINE_CONST.finditer(text):
            line_no = text[:m.start()].count("\n") + 1
            lines = text.splitlines()
            start = max(0, line_no - 2)
            end = min(len(lines), line_no + 2)
            preview = "\n".join(lines[start:end])
            rel = str(path.relative_to(REPO)).replace("\\", "/")
            version = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            # Fragile group indexing; recover via direct SemVer match on m.group(0)
            v_match = re.search(SEMVER, m.group(0))
            version = v_match.group(1) if v_match else "?"
            out.append(Candidate(
                candidate_id=_candidate_id(tech, "inline_const", rel, line_no),
                kind="inline_version_const",
                channel="scss/less source" if path.suffix in (".scss", ".less", ".sass")
                        else ("css body" if path.suffix == ".css" else "js body"),
                anchor=m.group("key"),
                version_observed=version,
                evidence=_make_evidence(rel, line_no, line_no + 2, preview),
                task_for_drafter=(
                    f"Draft a rule that captures the inline version constant "
                    f"shown in {rel} ('{m.group('key')}: {version}'). If this "
                    f"file ships to clients as-is (no build step), section "
                    f"is 'banner_rules' or a body-channel rule. If it's a "
                    f"build-time source that gets compiled (Sass / Less), "
                    f"prefer the COMPILED output's emitted form -- use "
                    f"retrieve_source on the matching .css output to find it."
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# Walker
# ---------------------------------------------------------------------------

def _iter_files(root: Path, suffixes: tuple[str, ...] | None):
    if not root.exists():
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = set(p.relative_to(root).parts)
        if parts & _SKIP_DIR_NAMES:
            continue
        if suffixes is not None and p.suffix.lower() not in suffixes:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


# ---------------------------------------------------------------------------
# Top-level: discover
# ---------------------------------------------------------------------------

def discover(tech: str, *, tech_dir: Path | None = None) -> dict:
    """Walk every ref dir under ``lab/research/<tech>/out/source/`` and
    return a dict suitable for direct serialisation to candidates.json.

    Returns ``{"tech": tech, "refs": [...], "candidates": [...]}``.
    """
    tech_dir = tech_dir or (RESEARCH / tech)
    source_root = tech_dir / "out" / "source"
    if not source_root.exists():
        return {"tech": tech, "refs": [], "candidates": []}
    refs: list[str] = []
    candidates: list[Candidate] = []
    for ref_dir in sorted(p for p in source_root.iterdir() if p.is_dir()):
        refs.append(ref_dir.name)
        candidates.extend(find_banners(tech, ref_dir))
        candidates.extend(find_package_metadata(tech, ref_dir))
        candidates.extend(find_inline_version_constants(tech, ref_dir))
    # Idempotency: dedup by candidate_id
    seen: set[str] = set()
    unique: list[Candidate] = []
    for c in candidates:
        if c.candidate_id in seen:
            continue
        seen.add(c.candidate_id)
        unique.append(c)
    return {
        "tech": tech,
        "refs": refs,
        "candidates": [asdict(c) for c in unique],
    }
