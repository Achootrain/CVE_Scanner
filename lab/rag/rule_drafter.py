"""Agent loop that drafts candidate rules_src.json rows (CLAUDE.md §12).

Output: ``lab/research/<tech>/rules_src_drafted.json``. NEVER lab.db.
Humans review; then ``research_cycle.py import-rules`` lands the approved
rules.

Loop shape:

    user gives a "task" string for tech T (e.g. "draft a banner rule
        for Font Awesome that captures version + edition").
    spans_seen = {}   # content_hash -> Span (the bounded-citation set)
    history = [Message(role="user", text=initial)]

    for turn in MAX_TURNS:
        out = gemini.generate(history, system=SYSTEM)
        step = json.loads(out)
        if step["tool"] == "draft":
            rule = step["rule"]
            if guardrails_fail(rule, spans_seen, rule_queries):
                history.append(failure feedback);  continue
            return rule
        # else: it's a tool call
        spans = TOOLS[step["tool"]](**step["args"])
        for s in spans:
            spans_seen[s.content_hash] = s
        history.append(Message("model", out))
        history.append(Message("user", f"[tool_result]\n{render(spans)}"))

    raise drafter exhausted

Guardrails (structural, run BEFORE the rule is written):

  1. bounded-citation: every citation in rule.source.citations must
     verify_citation(...) AND its content_hash must appear in spans_seen.
  2. self-match: rule.pattern compiles AND matches at least one cited
     span verbatim.
  3. §9 multi-phrased gate: drafter must call retrieve_rules with at
     least TWO textually-distinct paraphrasings of the signal shape.
     A single boolean "called once" is too easily satisfied -- §9 wants
     the drafter to actually fish for near-matches, not tick a box.
  4. post-draft duplicate check: after the rule is drafted, retrieve_rules
     is re-run with the drafted regex's literal anchor tokens as a query.
     If any existing rule shares >=2 of the same anchors AND drafter
     claimed ninth_gate_outcome='no_near_match', the draft is rejected
     and the near-matches are surfaced to the loop. This catches the
     case where the agent's pre-draft queries happened to miss a rule
     that the FINAL pattern is actually a near-duplicate of.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path

from lab.rag import retrieval as rt
from lab.rag.llm import GeminiClient, Message


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RESEARCH = REPO / "lab" / "research"

MAX_TURNS = 12
MAX_SPANS_PER_RESULT = 6     # trim retrieved spans before feeding back


# ---------------------------------------------------------------------------
# System prompt (the contract)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a fingerprinting-rule drafter. You author detection rules for a
single technology, grounded in the tech's own source code.

You operate in a strict tool-using JSON loop. Each turn you emit ONE JSON
object, which is EITHER a tool call OR a final draft. Never prose. Never
multiple objects.

Tools available (use them; do not invent rules from memory):

  retrieve_source(query: str, tech: str, k: int=10)
    -> Search the tech's release source code. Use this to find banner
       literals, build configs, version constants, canonical filenames.
       MANDATORY: you must call this at least once before drafting.

  retrieve_rules(signal_shape: str, tech: str|null=null, k: int=10)
    -> Search EXISTING rules for shapes similar to what you are about to
       draft. MANDATORY (§9 multi-phrased gate): you must call this at
       least TWICE before drafting, with TEXTUALLY DISTINCT phrasings of
       the signal shape (e.g. "banner header version" then "CSS comment
       version disclosure" -- not the same words restated). One phrasing
       isn't a survey. Then either confirm no near-match exists or
       articulate why your rule is a genuinely different signal shape.
       A post-draft scan ALSO re-runs retrieve_rules with your final
       regex's literal anchors -- if existing rules share >=2 of your
       anchors and you claimed 'no_near_match', the draft is rejected.

  retrieve_research(analog: str, tech: str|null=null, k: int=5)
    -> Search prior tech research artifacts (READMEs, prior rules).
       Optional. Useful for cross-tech analogy at the start.

  retrieve_policy(topic: str, k: int=3)
    -> Search CLAUDE.md. Optional. Use when triaging an ambiguous case.

Tool call form (emit exactly this shape):

  {"tool": "retrieve_source", "args": {"query": "...", "tech": "...", "k": 5}}

Final draft form (emit when you have enough evidence):

  {"tool": "draft",
   "rule": {
     "id": "<tech_short>_<descriptor>",
     "section": "banner_rules" | "url_version_in_path_rules" |
                "url_filename_rules" | "webfont_rules" |
                "css_class_rules" | "kit_rules" | "slug_url_rules",
     "kind":    "banner" | "url_version" | "url_filename" |
                "webfont" | "css_class" | "kit",
     "pattern": "<Python regex>",
     "extracts": {"version": {"g": 1}, ...},   // see notes
     "applies_to": "css body" | "js body" | "any URL" | ...,
     "confidence": "high" | "medium" | "low",
     "source": {
       "principle": "<1-sentence: WHY this regex captures the signal,\
 quoting or paraphrasing a specific file+line from a cited span>",
       "citations": [
         {"file_path": "<repo-relative path or lab.db:lab_src_rules#...>",
          "line_start": <int>, "line_end": <int>,
          "content_hash": "<sha256 from the span the retriever returned>"}
       ]
     },
     "note": "<optional one-liner>",
     "_drafter_meta": {
       "signal_shape": "<one-line description of the signal>",
       "ninth_gate_outcome": "no_near_match" | "generalised_from_<rule_id>" |
                             "novel_because_<short_reason>"
     }
   }
  }

Rules you MUST follow:

  - Every regex group you reference in `extracts` (e.g. {"g": 1}) must
    actually exist in `pattern`. Test mentally before emitting.
  - Citations MUST use content_hash values from spans returned this
    session. Do NOT invent hashes. Do NOT cite spans you have not seen.
  - The pattern MUST match at least one of your cited spans (verbatim
    substring match). If it doesn't, refine the pattern or pick a
    different span.
  - Prefer ONE rule that covers the signal shape over several rules per
    host / separator / release era (CLAUDE.md §7, §9).
  - If retrieve_rules surfaces a near-match, STOP and either generalise
    that rule or articulate why yours is genuinely different.

If you cannot draft a coherent rule with the evidence available, emit:

  {"tool": "draft", "rule": null,
   "_abort_reason": "<why you cannot proceed>"}

Do not emit anything else. Do not explain. JSON only.
"""


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def _trim_text(text: str, n: int = 800) -> str:
    return text if len(text) <= n else text[:n] + " ...[truncated]"


def _spans_to_payload(spans: list[rt.Span]) -> list[dict]:
    out = []
    for s in spans[:MAX_SPANS_PER_RESULT]:
        out.append({
            "source": s.source,
            "tech": s.tech,
            "file_path": s.file_path,
            "line_start": s.line_start,
            "line_end": s.line_end,
            "content_hash": s.content_hash,
            "score": round(s.score, 2),
            "text": _trim_text(s.text, 800),
        })
    return out


TOOLS = {
    "retrieve_source": rt.retrieve_source,
    "retrieve_rules": rt.retrieve_rules,
    "retrieve_research": rt.retrieve_research,
    "retrieve_policy": rt.retrieve_policy,
}


def _dispatch(step: dict) -> tuple[list[rt.Span], str | None, str | None]:
    """Run a tool call. Returns (spans, error, query_text). query_text is
    surfaced so the loop can record multi-phrased §9 gate inputs."""
    name = step.get("tool")
    fn = TOOLS.get(name)
    if fn is None:
        return [], f"unknown tool: {name!r}", None
    args = step.get("args") or {}
    # whitelist args by signature -- never pass arbitrary kwargs through.
    allowed = {"query", "signal_shape", "analog", "topic", "tech", "k"}
    args = {k: v for k, v in args.items() if k in allowed}
    # normalize: each retrieve_* uses a different "query" key name
    query = (args.pop("query", None) or args.pop("signal_shape", None)
             or args.pop("analog", None) or args.pop("topic", None))
    if query is None:
        return [], f"missing query arg for {name}", None
    try:
        spans = fn(query, **args)
    except (TypeError, FileNotFoundError) as e:
        return [], f"tool error: {e}", query
    return spans, None, query


# ---------------------------------------------------------------------------
# §9 multi-phrased gate helpers
# ---------------------------------------------------------------------------

# Words too generic to count as a "distinct phrasing" — they ride along on
# almost any signal-shape description and shouldn't be the only difference
# between two queries.
_QUERY_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "this", "that", "rule", "rules",
    "version", "tech", "shape", "signal", "near", "any", "all",
    "regex", "pattern", "match", "matches", "find", "search",
})
_QUERY_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")


def _query_tokens(q: str) -> set[str]:
    """Lower-cased >=3-char alphanumeric tokens minus stopwords."""
    return {t.lower() for t in _QUERY_TOKEN_RE.findall(q)
            if t.lower() not in _QUERY_STOPWORDS}


def _are_distinct_phrasings(queries: list[str]) -> bool:
    """True iff >=2 queries differ by a non-stopword token in EACH direction.

    Symmetric difference test: q1 must have a token q2 doesn't, AND vice
    versa. Pure-prefix queries ('jQuery version' vs 'jQuery version banner')
    don't count -- the agent must actually phrase differently, not just
    append.
    """
    if len(queries) < 2:
        return False
    token_sets = [_query_tokens(q) for q in queries]
    for i in range(len(token_sets)):
        for j in range(i + 1, len(token_sets)):
            a, b = token_sets[i], token_sets[j]
            if (a - b) and (b - a):
                return True
    return False


# ---------------------------------------------------------------------------
# Post-draft duplicate scan
# ---------------------------------------------------------------------------

# Strip regex metacharacters and escape sequences to recover the LITERAL
# anchor tokens a pattern is searching for. These anchors are the rule's
# fingerprint -- two rules sharing anchors are likely the same signal.
_REGEX_LITERAL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
_LITERAL_STOPWORDS = frozenset({"http", "https", "www", "com", "org", "net"})


def _literal_anchors_of_pattern(pattern: str) -> list[str]:
    """Extract literal alphanumeric anchors from a Python regex.

    Strips: escape sequences (\\d, \\w, \\s, \\., \\-, etc.), character
    classes [...], non-capturing groups (?:...), regex metacharacters
    (?*+|^$(){}.). What remains is the literal text the regex is matching.
    """
    s = pattern
    # Drop escape sequences first (otherwise we'd extract 'd' from '\\d').
    s = re.sub(r"\\[a-zA-Z]", " ", s)
    s = re.sub(r"\\.", " ", s)
    # Drop character classes wholesale -- they're not literal anchors.
    s = re.sub(r"\[[^\]]*\]", " ", s)
    # Drop group prefixes like (?P<name>, (?:, (?=, (?!.
    s = re.sub(r"\(\?[A-Za-z<=!:][^>)]*[>)]?", " ", s)
    # Strip remaining regex metacharacters.
    s = re.sub(r"[?*+|^$(){}.]", " ", s)
    toks = [t.lower() for t in _REGEX_LITERAL_RE.findall(s)
            if t.lower() not in _LITERAL_STOPWORDS]
    # Dedup, preserve order.
    seen: set[str] = set()
    out: list[str] = []
    for t in toks:
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def _post_draft_dup_check(rule: dict, tech: str,
                          *, k: int = 5,
                          retrieve_fn=None) -> list[str]:
    """Re-run retrieve_rules with the drafted regex's literal anchors.

    Flag if any existing rule for the same tech shares >=2 anchor tokens
    AND drafter claimed ninth_gate_outcome='no_near_match', OR if drafter
    claimed 'generalised_from_X' but X is not among the near-matches.

    retrieve_fn override exists for unit tests; production passes None
    and we use rt.retrieve_rules.
    """
    errs: list[str] = []
    pattern = (rule or {}).get("pattern") or ""
    if not pattern:
        return errs

    anchors = _literal_anchors_of_pattern(pattern)
    if len(anchors) < 2:
        # Patterns with <2 literal anchors are too generic for token-overlap
        # to be informative. Surface as a soft note via the drafter_meta.
        return errs

    meta = rule.get("_drafter_meta") or {}
    outcome = meta.get("ninth_gate_outcome") or ""

    query = " ".join(anchors[:5])
    fn = retrieve_fn if retrieve_fn is not None else rt.retrieve_rules
    try:
        hits = fn(query, tech=tech, k=k)
    except FileNotFoundError:
        # Index not built -- can't enforce post-draft check. Don't block
        # drafting on infrastructure; the human reviewer will catch dups.
        return errs

    near: list[tuple[str, set[str]]] = []
    for h in hits:
        other = set(_literal_anchors_of_pattern(h.text))
        overlap = set(anchors) & other
        if len(overlap) >= 2:
            rid = h.file_path  # e.g. "lab.db:lab_src_rules#tech/rule_id"
            near.append((rid, overlap))

    if not near:
        if outcome.startswith("generalised_from_"):
            # Drafter claimed to generalise from rule X but the post-draft
            # scan can't find X -- claim is unfalsifiable, push back.
            errs.append(
                "GUARDRAIL VIOLATION (post-draft): you claimed "
                f"ninth_gate_outcome='{outcome}' but the drafted regex's "
                "anchors don't surface that rule in retrieve_rules. Either "
                "the regex doesn't actually generalise it, or "
                "ninth_gate_outcome is mislabelled."
            )
        return errs

    near_ids = [n[0] for n in near]
    if outcome == "no_near_match":
        errs.append(
            "GUARDRAIL VIOLATION (post-draft dup check): you claimed "
            "ninth_gate_outcome='no_near_match' but the drafted regex's "
            f"literal anchors {anchors[:5]} surface these existing rule(s) "
            f"with >=2 shared anchors: {near_ids}. Either generalise one of "
            "them (set ninth_gate_outcome='generalised_from_<rule_id>') or "
            "articulate why the signal shape is genuinely different "
            "(set ninth_gate_outcome='novel_because_<reason>')."
        )
    elif outcome.startswith("generalised_from_"):
        claimed = outcome[len("generalised_from_"):]
        if not any(claimed in rid for rid in near_ids):
            errs.append(
                f"GUARDRAIL VIOLATION: ninth_gate_outcome='{outcome}' but "
                f"'{claimed}' is not among the near-matches surfaced by the "
                f"drafted regex: {near_ids}. Either fix the rule_id or "
                "rethink the generalisation claim."
            )
    return errs


# ---------------------------------------------------------------------------
# Guardrails (the structural enforcement)
# ---------------------------------------------------------------------------

def _verify_guardrails(rule: dict,
                       spans_seen: dict[str, rt.Span],
                       rule_queries: list[str],
                       *,
                       tech: str | None = None,
                       post_draft_retrieve_fn=None) -> list[str]:
    """Return a list of guardrail violation strings; empty list = PASS.

    Run BEFORE the rule is written. Violations get fed back to the model
    as a 'fix it' message so it can retry within the MAX_TURNS budget.

    ``rule_queries`` is the ordered list of query strings the drafter sent
    to retrieve_rules. The §9 multi-phrased gate requires >=2 textually
    distinct phrasings; see _are_distinct_phrasings.

    ``post_draft_retrieve_fn`` lets tests inject a fake retrieve_rules
    without touching the FTS index.
    """
    errs: list[str] = []

    # Guardrail #3: §9 multi-phrased gate
    if not rule_queries:
        errs.append(
            "GUARDRAIL VIOLATION (§9 gate): you must call retrieve_rules "
            "before drafting, with >=2 textually distinct phrasings of the "
            "signal shape."
        )
    elif len(rule_queries) < 2:
        errs.append(
            "GUARDRAIL VIOLATION (§9 multi-phrased gate): only one "
            f"retrieve_rules query so far ({rule_queries!r}). Call it again "
            "with a DIFFERENT phrasing (e.g. swap 'banner header version' "
            "for 'CSS comment version disclosure' or 'JS library version "
            "string'). One phrasing is not a survey."
        )
    elif not _are_distinct_phrasings(rule_queries):
        errs.append(
            "GUARDRAIL VIOLATION (§9 multi-phrased gate): your "
            f"retrieve_rules queries {rule_queries!r} share the same "
            "non-stopword tokens. Paraphrase: introduce a NEW vocabulary "
            "axis (channel, anchor style, file type, separator family). "
            "Each query must have a token the other doesn't."
        )

    src = (rule or {}).get("source") or {}
    citations = src.get("citations") or []
    if not citations:
        errs.append(
            "GUARDRAIL VIOLATION: rule.source.citations is empty. "
            "Cite at least one retrieved span."
        )

    # Guardrail #1: bounded-citation
    for i, cite in enumerate(citations):
        ch = cite.get("content_hash")
        if not ch:
            errs.append(f"citations[{i}].content_hash is missing")
            continue
        if ch not in spans_seen:
            errs.append(
                f"citations[{i}].content_hash {ch[:12]}... was not in any "
                f"retrieval result this session. Cite only spans you have "
                f"actually retrieved."
            )
            continue
        ok = rt.verify_citation(
            file_path=cite.get("file_path", ""),
            line_start=int(cite.get("line_start", 0)),
            line_end=int(cite.get("line_end", 0)),
            content_hash=ch,
        )
        if not ok:
            errs.append(
                f"citations[{i}] failed re-hash verification (file_path, "
                f"line range, and content_hash must all match what the "
                f"retriever returned)."
            )

    # Guardrail #2: self-match
    pattern = rule.get("pattern") if rule else None
    if not pattern:
        errs.append("rule.pattern is missing or empty")
    else:
        try:
            cre = re.compile(pattern)
        except re.error as e:
            errs.append(f"rule.pattern does not compile: {e}")
            cre = None
        if cre is not None:
            matched = False
            for cite in citations:
                ch = cite.get("content_hash")
                span = spans_seen.get(ch) if ch else None
                if span and cre.search(span.text):
                    matched = True
                    break
            if not matched:
                # Show the actual cited text so the model can SEE why the
                # regex doesn't fire. Without this, cheap models loop
                # re-submitting the same broken pattern.
                samples = []
                for cite in citations[:2]:
                    ch = cite.get("content_hash")
                    span = spans_seen.get(ch) if ch else None
                    if span:
                        samples.append(
                            f"  {cite.get('file_path')}:{cite.get('line_start')}-"
                            f"{cite.get('line_end')} (first 200 chars, repr):\n"
                            f"    {span.text[:200]!r}"
                        )
                errs.append(
                    "GUARDRAIL VIOLATION (self-match): rule.pattern does "
                    "not match any cited span. Your pattern was:\n"
                    f"    {pattern!r}\n"
                    "The cited span text is:\n" + "\n".join(samples)
                    + "\nLook at the EXACT characters between tokens "
                    "(asterisks, spaces, newlines). Refine the pattern."
                )

    # Extracts coherence
    extracts = rule.get("extracts") or {}
    if pattern:
        try:
            n_groups = re.compile(pattern).groups
        except re.error:
            n_groups = 0
        for key, spec in extracts.items():
            if isinstance(spec, dict) and "g" in spec:
                g = spec["g"]
                if not isinstance(g, int) or g < 1 or g > n_groups:
                    errs.append(
                        f"extracts.{key}.g={g} but pattern has {n_groups} group(s)"
                    )

    # Guardrail #4: post-draft dup check. Only run if everything above
    # passed; no point dup-checking a rule that fails self-match.
    if not errs and tech and pattern:
        errs.extend(_post_draft_dup_check(
            rule, tech, retrieve_fn=post_draft_retrieve_fn))

    return errs


# ---------------------------------------------------------------------------
# Candidate -> task string
# ---------------------------------------------------------------------------

def build_task_from_candidate(cand: dict) -> str:
    """Render a candidate dict (from lab.core.discover) into the task string
    the drafter consumes. Preserves enough evidence (file/lines/preview/
    observed version) for the drafter's first retrieve_source query to
    succeed without guessing."""
    base = cand.get("task_for_drafter") or ""
    ev = cand.get("evidence") or {}
    preview = (ev.get("preview") or "")[:300]
    return (
        f"{base}\n\n"
        f"Candidate metadata:\n"
        f"  kind:             {cand.get('kind')}\n"
        f"  channel:          {cand.get('channel')}\n"
        f"  anchor token:     {cand.get('anchor')}\n"
        f"  version_observed: {cand.get('version_observed')}\n"
        f"  evidence file:    {ev.get('file_path')}:"
        f"{ev.get('line_start')}-{ev.get('line_end')}\n"
        f"  evidence preview (verbatim, for orientation only -- you MUST "
        f"still retrieve_source to get a span with content_hash to cite):\n"
        f"    {preview!r}\n\n"
        f"Begin by querying retrieve_rules for existing rules near this "
        f"signal shape (§9 gate), then retrieve_source for the cited file, "
        f"then draft."
    )


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

def draft_rule(client: GeminiClient, tech: str, task: str,
               *, verbose: bool = False) -> dict:
    """Drive the ReAct loop for one task. Returns the drafted rule on
    success, or a dict with ``_aborted`` reason on failure."""

    history: list[Message] = [Message(
        role="user",
        text=(
            f"tech_slug: {tech}\n"
            f"task: {task}\n\n"
            "Begin. Remember: JSON only, one object per turn. Call "
            "retrieve_rules at least TWICE with DIFFERENT phrasings of the "
            "signal shape (§9 multi-phrased gate), retrieve_source at least "
            "once, then emit the draft."
        ),
    )]
    spans_seen: dict[str, rt.Span] = {}
    rule_queries: list[str] = []

    for turn in range(MAX_TURNS):
        raw = client.generate(history, system=SYSTEM_PROMPT)
        if verbose:
            print(f"--- turn {turn} ---\n{raw[:400]}\n", file=sys.stderr)
        try:
            step = json.loads(raw)
        except json.JSONDecodeError as e:
            history.append(Message("model", raw))
            history.append(Message("user",
                f"Your last output was not valid JSON ({e}). "
                "Emit ONE JSON object. JSON only."))
            continue
        history.append(Message("model", raw))

        if step.get("tool") == "draft":
            rule = step.get("rule")
            if rule is None:
                return {"_aborted": step.get("_abort_reason", "drafter returned null rule")}
            errs = _verify_guardrails(rule, spans_seen, rule_queries, tech=tech)
            if not errs:
                rule.setdefault("_drafter_meta", {})["turns_used"] = turn + 1
                rule["_drafter_meta"]["rule_queries"] = list(rule_queries)
                return rule
            if verbose:
                print(f"guardrail violations: {errs}", file=sys.stderr)
            history.append(Message("user",
                "Your draft failed guardrails:\n" + "\n".join(f"  - {e}" for e in errs)
                + "\n\nFix the issues and emit a new draft (or call more tools first)."))
            continue

        spans, err, query = _dispatch(step)
        if err:
            history.append(Message("user", f"[tool_error] {err}"))
            continue
        if step["tool"] == "retrieve_rules" and query is not None:
            rule_queries.append(query)
        for s in spans:
            spans_seen[s.content_hash] = s
        history.append(Message("user",
            f"[tool_result name={step['tool']} hits={len(spans)}]\n"
            + json.dumps(_spans_to_payload(spans), ensure_ascii=False)))

    return {"_aborted": f"drafter exhausted MAX_TURNS={MAX_TURNS}"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Draft a candidate rule via Gemini + RAG retrieval."
    )
    ap.add_argument("tech_slug")
    ap.add_argument("--task", required=True,
                    help="natural-language description of what to draft")
    ap.add_argument("--out", default=None,
                    help="output path (default: lab/research/<tech>/rules_src_drafted.json)")
    ap.add_argument("--model", default=None, help="override Gemini model")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    out_path = Path(args.out) if args.out else (
        RESEARCH / args.tech_slug / "rules_src_drafted.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    client = GeminiClient(model=args.model) if args.model else GeminiClient()
    rule = draft_rule(client, args.tech_slug, args.task, verbose=args.verbose)

    # Merge into existing drafted file (one section per draft, by id).
    existing = {"rules": []}
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    existing.setdefault("rules", []).append(rule)
    out_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps(rule, indent=2, ensure_ascii=False))
    print(f"\nwritten to {out_path}", file=sys.stderr)
    return 0 if "_aborted" not in rule else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
