"""Claude Sonnet judge for drafted rules (CLAUDE.md §12).

The drafter (Gemini Flash-Lite) emits a rule that passes structural
guardrails: bounded-citation, self-match, multi-phrased §9 gate,
post-draft dup check. None of those checks reason about whether the rule
is GOOD -- they verify it isn't structurally broken or a duplicate.

This module asks a stronger model (Claude Sonnet) three semantic
questions per §12 model-choice section:

  1. Signal-shape coherence (§7)
     Does the regex describe ONE coherent signal shape, or two-things-
     glued-with-|? Per §7 the signal is a TOKEN naming the tech in
     PROXIMITY to a VERSION. Patterns that enumerate samples (rule-per-
     CDN-host, rule-per-separator) get FLAGGED.

  2. Inventory-matching sanity-check (§9)
     The structural post-draft check already rejects "claim no_near_match
     but anchors overlap with an existing rule". The judge sanity-checks
     the OPPOSITE direction: when drafter says "generalised_from_X" or
     "novel_because_Y", does the cited evidence actually support that?

  3. Channel-choice sanity (§7a)
     The funnel has stages (URL extract, body extract, inline extract,
     bundle scan). A rule's section/applies_to must match the stage the
     pattern actually fires in. A 'banner_rules' rule whose pattern only
     fires on URLs is mis-channelled.

Output: {"verdict": "PASS"|"FLAG", "reasons": [...], "checks": {...}}.

The judge ADVISES; it does NOT block import. The human reviewer reads
the verdict before approving rules_src_drafted.json -> rules_src.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

from lab.rag import retrieval as rt
from lab.rag.llm import AnthropicClient, GeminiClient, load_rag_config


def _build_judge_client(model_override: str | None = None) -> Any:
    """Instantiate the judge client per lab/rag/config.json.

    Provider can be 'gemini' or 'anthropic'. Both clients expose
    ``generate_text(text, *, system)``; the judge consumes that uniform
    shape and doesn't care which provider is behind it.
    """
    cfg = (load_rag_config().get("judge") or {})
    provider = (cfg.get("provider") or "gemini").lower()
    model = model_override or cfg.get("model")
    if provider == "anthropic":
        return AnthropicClient(model=model) if model else AnthropicClient()
    if provider == "gemini":
        return GeminiClient(model=model) if model else GeminiClient()
    raise ValueError(
        f"unknown judge provider in config.json: {provider!r}; "
        "expected 'gemini' or 'anthropic'"
    )


JUDGE_SYSTEM_PROMPT = """\
You are reviewing a fingerprinting-rule drafted by a junior agent for the
project described in CLAUDE.md. You receive: the drafted rule, the
agent's claimed ninth_gate_outcome, a preview of the cited spans, and
near-matches surfaced by retrieve_rules. Emit ONE JSON object:

  {"verdict": "PASS" | "FLAG",
   "reasons": ["short specific reason", ...],
   "checks": {
     "signal_coherence":     "PASS"|"FLAG",
     "inventory_matching":   "PASS"|"FLAG",
     "channel_choice":       "PASS"|"FLAG"
   }}

JSON only. No prose. No markdown. No code fences.

Three checks:

1. SIGNAL COHERENCE (CLAUDE.md §7)
   The signal is: a TOKEN naming the tech, in PROXIMITY to a VERSION.
   FLAG when the regex is two-things-glued-with-`|`, enumerates samples
   (one branch per CDN host, one per separator character), pins token
   position, or hard-codes path noise specific to one source. PASS when
   the pattern describes ONE coherent signal that absorbs casing,
   separators, and intermediate path noise without enumerating them.

2. INVENTORY MATCHING (CLAUDE.md §9)
   The drafter claimed `ninth_gate_outcome` is one of:
     no_near_match | generalised_from_<rule_id> | novel_because_<reason>
   Sanity-check the claim against the surfaced near-matches:
   - no_near_match + zero near-matches:                  PASS
   - no_near_match + near-matches sharing anchors:       FLAG
       (the post-draft check already catches this; if you see it slip
        through it means the structural check was bypassed)
   - generalised_from_X + X is in near-matches:          PASS
       Bonus check: does the new pattern ACTUALLY generalise X, or just
       restate it? If it doesn't add coverage, FLAG.
   - novel_because_<reason> + the reason matches a clear signal-shape
     difference visible in cited spans:                  PASS
   - novel_because_<reason> + reason is hand-wavy:       FLAG

3. CHANNEL CHOICE (CLAUDE.md §7a)
   `section` must align with where the pattern fires:
     banner_rules               -> pattern fires on CSS/JS file BODIES
     url_version_in_path_rules  -> pattern fires on URLs (slashes, ?ver=)
     url_filename_rules         -> pattern fires on URL filenames
     webfont_rules              -> pattern fires on font filenames or
                                   @font-face src() values
     css_class_rules            -> pattern fires on HTML class attrs
     kit_rules                  -> pattern fires on kit-loader JS
     slug_url_rules             -> pattern fires on WP plugin/theme slugs
   `applies_to` must match `section` ("css body" / "js body" / "any URL"
   / etc.). FLAG when the pattern's literal anchors clearly belong to a
   different channel.

Verdict aggregation: ANY check = FLAG -> overall verdict = FLAG. All
three PASS -> verdict = PASS.

Reasons MUST cite a SPECIFIC element of the rule (anchor token, group
index, claimed gate outcome, section name). Avoid generic phrasing like
"could be improved" -- that's not actionable.
"""


def _build_input_payload(rule: dict, tech: str,
                         nearby_rules: list[dict],
                         cited_spans_preview: list[dict]) -> str:
    return json.dumps({
        "tech": tech,
        "rule": rule,
        "nearby_rules_surfaced": nearby_rules,
        "cited_spans_preview": cited_spans_preview,
    }, ensure_ascii=False, indent=2)


def _summarise_nearby(rule: dict, tech: str, *, k: int = 5,
                      retrieve_fn: Callable | None = None) -> list[dict]:
    """Pull existing rules near the drafted regex's literal anchors so the
    judge can read them. Mirrors the post-draft dup check's input."""
    pattern = (rule or {}).get("pattern") or ""
    if not pattern:
        return []
    # Reuse the drafter's anchor extractor; importing here avoids circular
    # import at module load.
    from lab.rag.rule_drafter import _literal_anchors_of_pattern
    anchors = _literal_anchors_of_pattern(pattern)
    if not anchors:
        return []
    fn = retrieve_fn if retrieve_fn is not None else rt.retrieve_rules
    try:
        hits = fn(" ".join(anchors[:5]), tech=tech, k=k)
    except FileNotFoundError:
        return []
    return [
        {
            "rule_ref": h.file_path,
            "score": round(h.score, 2),
            "text_first_400": (h.text or "")[:400],
        }
        for h in hits
    ]


def judge_rule(rule: dict, tech: str, *,
               client: Any | None = None,
               nearby_rules: list[dict] | None = None,
               cited_spans_preview: list[dict] | None = None,
               retrieve_fn: Callable | None = None) -> dict:
    """Run the judge over a drafted rule.

    Provider is chosen by lab/rag/config.json (gemini or anthropic).
    Tests inject a fake ``client`` whose ``.generate_text()`` returns a
    canned JSON string -- no network. Production pulls nearby_rules
    itself via retrieve_fn.

    Returns ``{"verdict": "PASS"|"FLAG", "reasons": [...], "checks": {...}}``.
    """
    if nearby_rules is None:
        nearby_rules = _summarise_nearby(rule, tech, retrieve_fn=retrieve_fn)
    if cited_spans_preview is None:
        # When called standalone (e.g. judging a pre-written rule), the
        # spans may not be available. Pass through whatever the caller
        # gave us, or an empty list.
        cited_spans_preview = []

    if client is None:
        client = _build_judge_client()

    payload = _build_input_payload(rule, tech, nearby_rules, cited_spans_preview)
    # Both GeminiClient and AnthropicClient expose generate_text(text, *, system).
    raw = client.generate_text(payload, system=JUDGE_SYSTEM_PROMPT)
    try:
        out = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "verdict": "FLAG",
            "reasons": [f"judge returned non-JSON output: {raw[:200]!r}"],
            "checks": {},
        }

    # Normalize: ensure required keys exist and verdict is one of the two
    # allowed values. Anthropic is generally compliant but defensive
    # coding protects downstream consumers (CLI prints, gh checks etc.).
    verdict = out.get("verdict")
    if verdict not in ("PASS", "FLAG"):
        return {
            "verdict": "FLAG",
            "reasons": [f"judge emitted invalid verdict={verdict!r}; raw={raw[:200]!r}"],
            "checks": out.get("checks") or {},
        }
    return {
        "verdict": verdict,
        "reasons": out.get("reasons") or [],
        "checks": out.get("checks") or {},
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    """Judge every rule in a rules_src_drafted.json file.

    Writes lab/research/<tech>/rules_src_judged.json with the same rules
    plus a ``_judge`` block on each.
    """
    import argparse
    REPO = Path(__file__).resolve().parents[2]
    RESEARCH = REPO / "lab" / "research"

    ap = argparse.ArgumentParser(
        description="Run the judge over drafted rules (provider per lab/rag/config.json)."
    )
    ap.add_argument("tech_slug")
    ap.add_argument("--in", dest="in_path", default=None,
                    help="rules_src_drafted.json path (default per-tech)")
    ap.add_argument("--out", default=None,
                    help="output path (default: rules_src_judged.json)")
    ap.add_argument("--model", default=None,
                    help="override the model from config.json")
    args = ap.parse_args(argv)

    in_path = Path(args.in_path) if args.in_path else (
        RESEARCH / args.tech_slug / "rules_src_drafted.json")
    out_path = Path(args.out) if args.out else (
        RESEARCH / args.tech_slug / "rules_src_judged.json")

    if not in_path.exists():
        print(f"input not found: {in_path}", file=sys.stderr)
        return 2

    data = json.loads(in_path.read_text(encoding="utf-8"))
    rules = data.get("rules") or []
    if not rules:
        print("no rules to judge", file=sys.stderr)
        return 0

    client = _build_judge_client(model_override=args.model)

    pass_n = flag_n = aborted_n = 0
    judged: list[dict] = []
    for rule in rules:
        if "_aborted" in rule or not rule.get("pattern"):
            aborted_n += 1
            judged.append(rule)
            continue
        verdict = judge_rule(rule, args.tech_slug, client=client)
        rule = dict(rule)
        rule["_judge"] = verdict
        judged.append(rule)
        if verdict["verdict"] == "PASS":
            pass_n += 1
        else:
            flag_n += 1

    out_path.write_text(
        json.dumps({"rules": judged}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"judged {len(rules)} rules: {pass_n} PASS, {flag_n} FLAG, {aborted_n} skipped")
    print(f"written to {out_path}")
    return 0 if flag_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
