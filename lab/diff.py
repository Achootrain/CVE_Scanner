"""Lab phase 3 — candidate version-extractor miner.

Reads a directory of per-fixture recordings produced by `lab/record.py`,
groups them by technology, pairs adjacent versions, and reports contexts
where the version string appears at the same position in both responses.

Those contexts are high-signal candidates for new version extractors: if
a body prefix/suffix is identical across two versions except for the
version number itself, it is very likely a disclosure template emitted by
the server.

Usage:
    python lab/diff.py --indir lab/out/phase3-demo
    python lab/diff.py --indir lab/out/phase3-demo --json lab/out/phase3-demo/candidates.json

Emits one report per technology under `<indir>/candidates/<tech>.md` plus
a machine-readable `<indir>/candidates.json`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# How many chars of context to capture around each version hit. Big enough
# to anchor uniqueness ("nginx/" vs " v") but small enough that a single
# HTML line rarely contains multiple hits that overlap windows.
WINDOW = 48
# When paired windows disagree character-for-character, allow small cosmetic
# drift (trailing whitespace, redundant spaces). We still require exact match
# after normalization.
WS_RE = re.compile(r"\s+")


@dataclass
class Candidate:
    tech: str
    version_a: str
    version_b: str
    source: str          # "header" | "body"
    path: str            # request path where this hit was first observed
    location: str        # header name, or "body" for body hits
    regex: str           # Python regex with a single (\S+) in the version slot
    example_a: str       # the exact window from fixture A (incl. the version)
    example_b: str       # the exact window from fixture B
    confidence: str      # "high" | "medium"
    # Paths where this exact (location, regex) pair fired. Populated by the
    # merge step so a single semantic pattern that shows up on N paths is
    # reported once with evidence, not N times.
    paths: list[str] = field(default_factory=list)
    # Version pairs whose comparison produced this candidate. In a 2-fixture
    # pair diff this is always a single entry; in a multi-version sweep a
    # candidate that holds across every adjacent pair gets len(N-1) entries.
    # Broader coverage = stronger proof that the regex is truly version-
    # discriminating and not an artifact of one specific pair.
    version_pairs: list[tuple[str, str]] = field(default_factory=list)

    def key(self) -> tuple:
        # A pattern's identity is (what it looks for, where it looks) —
        # not which request path surfaced it. A Server header leaks the same
        # version on every path; a default-404 template is shared across
        # every unknown path. Both should collapse to one candidate.
        return (self.tech, self.source, self.location, self.regex)


@dataclass
class TechGroup:
    tech: str
    fixtures: list[dict] = field(default_factory=list)   # recording payloads


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_recordings(indir: Path) -> dict[str, TechGroup]:
    groups: dict[str, TechGroup] = {}
    for rec_file in sorted(indir.glob("*/responses.json")):
        try:
            payload = json.loads(rec_file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[warn] cannot parse {rec_file}: {e}", file=sys.stderr)
            continue
        tech = payload.get("tech", "").strip()
        if not tech:
            continue
        key = tech.lower()
        groups.setdefault(key, TechGroup(tech=tech)).fixtures.append(payload)
    return groups


# ---------------------------------------------------------------------------
# Version ordering
# ---------------------------------------------------------------------------


_VER_NUM = re.compile(r"\d+")


def _version_key(v: str) -> tuple:
    # Split on non-digits so 1.25.3 → (1, 25, 3); fall back to string for oddities.
    parts = _VER_NUM.findall(v)
    if not parts:
        return (0, v)
    return tuple(int(p) for p in parts)


def pair_versions(fixtures: list[dict]) -> list[tuple[dict, dict]]:
    """Return adjacent-version pairs for diffing.

    Sorted by version key; consecutive pairs are returned. For technologies
    with only one fixture, returns empty (nothing to diff)."""
    if len(fixtures) < 2:
        return []
    sorted_fx = sorted(fixtures, key=lambda f: _version_key(f.get("version", "")))
    return [(sorted_fx[i], sorted_fx[i + 1]) for i in range(len(sorted_fx) - 1)]


# ---------------------------------------------------------------------------
# Version-hit extraction
# ---------------------------------------------------------------------------


def find_hits(text: str, version: str, window: int = WINDOW) -> list[tuple[int, str, str]]:
    """Return list of (offset, pre, post) where `version` appears in `text`."""
    if not text or not version:
        return []
    hits: list[tuple[int, str, str]] = []
    i = 0
    n = len(text)
    vlen = len(version)
    while True:
        k = text.find(version, i)
        if k < 0:
            break
        lo = max(0, k - window)
        hi = min(n, k + vlen + window)
        hits.append((k, text[lo:k], text[k + vlen:hi]))
        i = k + vlen
    return hits


def _norm(s: str) -> str:
    return WS_RE.sub(" ", s).strip()


def _escape_slot(pre: str, post: str) -> str:
    # Regex: escape the literal context, insert (\S+) for the version slot.
    return re.escape(pre) + r"(\S+)" + re.escape(post)


# ---------------------------------------------------------------------------
# Pairwise comparison
# ---------------------------------------------------------------------------


def compare_responses(
    tech: str,
    a: dict,
    b: dict,
) -> list[Candidate]:
    """Mine candidates from a pair of recordings for the same tech."""
    va, vb = a.get("version", ""), b.get("version", "")
    if not va or not vb:
        return []

    # Index fixture B responses by path for fast lookup.
    b_by_path: dict[str, dict] = {r["path"]: r for r in b.get("responses", []) if "path" in r}

    cands: list[Candidate] = []

    for ra in a.get("responses", []):
        if "error" in ra:
            continue
        path = ra.get("path")
        rb = b_by_path.get(path)
        if not rb or "error" in rb:
            continue

        # --- Headers ---
        headers_a = ra.get("headers", {}) or {}
        headers_b = rb.get("headers", {}) or {}
        for hname, hval_a in headers_a.items():
            hval_b = headers_b.get(hname)
            if not hval_b or not isinstance(hval_a, str):
                continue
            if va not in hval_a or vb not in hval_b:
                continue
            # Template the version out and require identical shape.
            templ_a = hval_a.replace(va, "\0")
            templ_b = hval_b.replace(vb, "\0")
            if templ_a != templ_b:
                continue
            # Confidence: full value is version-only → medium (no anchor);
            # has surrounding literal context → high.
            confidence = "high" if templ_a.replace("\0", "").strip() else "medium"
            # Build regex: anchored to start-of-value for header matching.
            pre, _, post = templ_a.partition("\0")
            regex = _escape_slot(pre, post)
            cands.append(Candidate(
                tech=tech,
                version_a=va,
                version_b=vb,
                source="header",
                path=path,
                location=hname,
                regex=regex,
                example_a=hval_a,
                example_b=hval_b,
                confidence=confidence,
                version_pairs=[(va, vb)],
            ))

        # --- Body ---
        body_a = ra.get("body") or ""
        body_b = rb.get("body") or ""
        if not body_a or not body_b:
            continue
        if body_a.startswith("<binary:") or body_b.startswith("<binary:"):
            continue
        # Skip if response status differs materially (e.g. 200 vs 500) —
        # different code paths produce different templates and aren't
        # comparable. 2xx-vs-2xx, 3xx-vs-3xx, 4xx-vs-4xx, 5xx-vs-5xx all ok.
        if (ra.get("status", 0) // 100) != (rb.get("status", 0) // 100):
            continue

        hits_a = find_hits(body_a, va)
        hits_b = find_hits(body_b, vb)
        if not hits_a or not hits_b:
            continue

        # For each hit in A, search for a matching context in B. We match on
        # normalized pre+post so minor whitespace drift doesn't kill signal.
        b_norm_index: dict[tuple[str, str], tuple[str, str]] = {}
        for _, pre_b, post_b in hits_b:
            b_norm_index[(_norm(pre_b), _norm(post_b))] = (pre_b, post_b)

        seen: set[tuple[str, str]] = set()
        for _, pre_a, post_a in hits_a:
            key = (_norm(pre_a), _norm(post_a))
            if key in seen:
                continue
            if key not in b_norm_index:
                continue
            pre_b, post_b = b_norm_index[key]
            # Use the A pre/post for the regex (either works — they're equal
            # after normalization; pick A deterministically).
            regex = _escape_slot(pre_a, post_a)
            # Confidence: shorter anchor strings are less unique. Require at
            # least 6 non-whitespace chars combined for "high".
            anchor_len = len(_norm(pre_a)) + len(_norm(post_a))
            confidence = "high" if anchor_len >= 6 else "medium"
            seen.add(key)
            cands.append(Candidate(
                tech=tech,
                version_a=va,
                version_b=vb,
                source="body",
                path=path,
                location="body",
                regex=regex,
                example_a=pre_a + va + post_a,
                example_b=pre_b + vb + post_b,
                confidence=confidence,
                version_pairs=[(va, vb)],
            ))

    return cands


# ---------------------------------------------------------------------------
# Dedup + report
# ---------------------------------------------------------------------------


def dedup(cands: list[Candidate], total_pairs: int = 1) -> list[Candidate]:
    """Merge duplicate candidates, rolling paths and version_pairs in.

    `total_pairs` is the number of adjacent version pairs tested for this
    tech. Confidence is downgraded to "medium" when a candidate fails to
    replicate across every pair, because a pattern that only holds for
    ONE pair out of many is likely a coincidence (e.g. a version number
    happening to appear inside an unrelated hash or build id)."""
    merged: dict[tuple, Candidate] = {}
    for c in cands:
        k = c.key()
        existing = merged.get(k)
        if existing is None:
            # First sighting — seed paths/version_pairs with the first hit.
            if c.path and c.path not in c.paths:
                c.paths = [c.path]
            if not c.version_pairs:
                c.version_pairs = [(c.version_a, c.version_b)]
            merged[k] = c
            continue
        if c.path and c.path not in existing.paths:
            existing.paths.append(c.path)
        for vp in c.version_pairs or [(c.version_a, c.version_b)]:
            if vp not in existing.version_pairs:
                existing.version_pairs.append(vp)

    # Recompute confidence using pair coverage.
    for c in merged.values():
        covered = len(c.version_pairs)
        # A candidate that replicates across every adjacent pair is
        # high-confidence regardless of anchor strength: if (\S+) captures
        # the right semver across N independent comparisons, the regex is
        # load-bearing. Conversely, if we only tested one pair (total=1),
        # the best we can do is trust the original anchor-length signal —
        # so don't downgrade from what compare_responses already computed.
        if total_pairs <= 1:
            continue
        if covered >= total_pairs:
            c.confidence = "high"
        else:
            c.confidence = "medium"
    return list(merged.values())


def render_markdown(tech: str, cands: list[Candidate]) -> str:
    if not cands:
        return f"# {tech} — candidate version extractors\n\nNo candidates found.\n"
    lines = [f"# {tech} — candidate version extractors", ""]
    header_cands = [c for c in cands if c.source == "header"]
    body_cands = [c for c in cands if c.source == "body"]

    def _fmt_block(title: str, bucket: list[Candidate]) -> None:
        if not bucket:
            return
        lines.append(f"## {title}")
        lines.append("")
        # Sort by breadth of evidence — pair coverage is the stronger signal
        # (it's what proves the regex is truly version-discriminating);
        # path count is the secondary tiebreaker.
        for c in sorted(bucket, key=lambda x: (-len(x.version_pairs), -len(x.paths))):
            loc = c.location
            pair_strs = [f"{a}↔{b}" for a, b in c.version_pairs]
            lines.append(f"- **{loc}** ({c.confidence}) — pairs ({len(pair_strs)}): "
                         f"{', '.join(pair_strs)}")
            lines.append(f"    - regex: `{c.regex}`")
            lines.append(f"    - paths ({len(c.paths)}): {', '.join(c.paths[:6])}" +
                         (" ..." if len(c.paths) > 6 else ""))
            lines.append(f"    - example: `{c.example_a.strip()[:160]}`")
        lines.append("")

    _fmt_block("Headers", header_cands)
    _fmt_block("Bodies", body_cands)
    return "\n".join(lines)


def write_reports(indir: Path, by_tech: dict[str, list[Candidate]]) -> None:
    outdir = indir / "candidates"
    outdir.mkdir(parents=True, exist_ok=True)
    # Per-tech markdown
    for tech, cands in by_tech.items():
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", tech.lower()).strip("_") or "unknown"
        (outdir / f"{safe}.md").write_text(render_markdown(tech, cands), encoding="utf-8")
    # Machine-readable roll-up
    roll = {
        tech: [c.__dict__ for c in cands] for tech, cands in by_tech.items()
    }
    (outdir / "candidates.json").write_text(
        json.dumps(roll, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_diff(indir: Path) -> dict[str, list[Candidate]]:
    groups = load_recordings(indir)
    by_tech: dict[str, list[Candidate]] = {}
    for key, group in groups.items():
        pairs = pair_versions(group.fixtures)
        if not pairs:
            continue
        all_cands: list[Candidate] = []
        for a, b in pairs:
            all_cands.extend(compare_responses(group.tech, a, b))
        by_tech[group.tech] = dedup(all_cands, total_pairs=len(pairs))
    return by_tech


def main() -> int:
    ap = argparse.ArgumentParser(description="Mine candidate version extractors from recordings.")
    ap.add_argument("--indir", required=True, help="Directory containing <fixture>/responses.json trees")
    args = ap.parse_args()

    indir = Path(args.indir)
    if not indir.is_dir():
        print(f"ERROR: {indir} is not a directory", file=sys.stderr)
        return 2

    by_tech = run_diff(indir)
    write_reports(indir, by_tech)

    # Console summary
    total = sum(len(v) for v in by_tech.values())
    print(f"\nTech groups with pairs: {len(by_tech)}")
    for tech, cands in by_tech.items():
        hdr = sum(1 for c in cands if c.source == "header")
        body = sum(1 for c in cands if c.source == "body")
        high = sum(1 for c in cands if c.confidence == "high")
        print(f"  {tech}: {len(cands)} candidate(s) — {hdr} header, {body} body — {high} high-confidence")
    print(f"\nTotal: {total} candidate(s). Reports under {indir / 'candidates'}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
