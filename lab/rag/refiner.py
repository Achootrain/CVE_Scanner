"""Regex refiner — widen an existing rule to cover counter-examples.

Companion to ``lab/rag/rule_drafter.py``. The drafter authors NEW rules
from a single tech's source; the refiner WIDENS an existing rule when
production scans surface bodies the rule should match but doesn't.

Scope (per the user-clarified 2026-05-21 design):
  - Regex-only. The refiner NEVER proposes new sibling rules; it edits
    the pattern of the existing row. Per CLAUDE.md §9 ("generalise when
    same signal shape + one absorbable variation").
  - Counter-examples are EXPLICITLY-PROVIDED spans, not derived from
    the corpus. The §6 anti-pattern stays out: the caller saves the
    fetched body as a snapshot first, then passes the snapshot Span here.

Structural guardrails (run BEFORE the judge gets the refined rule):
  G1. Self-match-original: refined pattern MUST match every span the
      original rule cited.
  G2. Self-match-counters: refined pattern MUST match every counter-
      example span.
  G3. Compiles + same capture-group arity for ``extracts``.
  G4. Pattern actually CHANGED. Refusing to widen is itself a signal --
      should be surfaced as `_aborted: refiner_no_change` so the loop
      doesn't spin.

If G1 fails the widening is a regression; the loop must reject the
proposal regardless of what the judge says. G1 is the monotonic-coverage
hard floor.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from lab.rag import retrieval as rt
from lab.rag.llm import GeminiClient, Message


MAX_TURNS = 6   # Refiner has less work than the drafter (no source-grounding).


REFINER_SYSTEM_PROMPT = """\
You are a regex refiner. You receive (1) an existing rule that matches
some spans but misses others, and (2) the counter-example spans it
needs to also match. Your job is to emit ONE JSON object with a WIDENED
regex that matches BOTH the original cited spans AND the counter-examples.

Constraints (CLAUDE.md §7, §9):

  - Generalise; do not enumerate. Absorb the variation between original
    and counters as ONE coherent change (separator, casing, optional
    prefix, intermediate noise) -- not as `(originalA|counterB)`
    branches glued with `|`. Per §7 "Anti-patterns: Rule per CDN host.
    Pinning separator to one character. Hard-coding token position".

  - Keep the same capture group used by `extracts` (g=1 by default).
    Adding non-capturing groups `(?:...)` is fine; adding extra
    capturing groups shifts the indices and breaks downstream consumers.

  - Refuse to over-widen. If the only way to match a counter-example
    is to add a wildcard so loose it would match unrelated tech (e.g.
    `.*\\d+\\.\\d+`), abort instead: emit
    {"tool": "refine", "rule": null, "_abort_reason": "<why>"}.

  - You may see a `pattern_history` array of prior attempts. Do NOT
    repeat one; the structural validator will reject it. Each entry
    has `{pattern, failed_because}` -- use it.

Output (emit exactly ONE JSON object, JSON only, no prose):

  Success:
    {"tool": "refine",
     "rule": {
       "pattern": "<new Python regex>",
       "_drafter_meta": {
         "refined_from": "<original pattern verbatim>",
         "widening_summary": "<one sentence: what variation you absorbed>",
         "signal_shape": "<one-line description>"
       }
     }}

  Failure to refine without over-widening:
    {"tool": "refine", "rule": null, "_abort_reason": "<short reason>"}
"""


@dataclass
class CounterExample:
    """One span the refined rule must also match."""
    file_path: str
    line_start: int
    line_end: int
    content_hash: str
    text: str

    @classmethod
    def from_span(cls, s: rt.Span) -> "CounterExample":
        return cls(
            file_path=s.file_path, line_start=s.line_start,
            line_end=s.line_end, content_hash=s.content_hash, text=s.text,
        )

    def to_payload(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "content_hash": self.content_hash,
            "text_first_300": self.text[:300],
        }


# ---------------------------------------------------------------------------
# Structural guardrails (run BEFORE the judge sees anything)
# ---------------------------------------------------------------------------

def _verify_refiner_guardrails(
    new_pattern: str,
    original_pattern: str,
    original_cited_texts: list[str],
    counter_example_texts: list[str],
    extracts: dict | None,
) -> list[str]:
    """Hard structural checks. ANY violation = the loop rejects the
    proposal regardless of what the judge says. This is the monotonic-
    coverage floor."""
    errs: list[str] = []

    # G4: pattern actually changed
    if new_pattern == original_pattern:
        errs.append(
            "GUARDRAIL VIOLATION (no-op): refined pattern is identical to "
            "the original. If counter-examples can't be absorbed, emit "
            "{rule: null, _abort_reason: ...} instead of returning the "
            "same regex."
        )

    # G3: compiles
    try:
        cre = re.compile(new_pattern)
    except re.error as e:
        errs.append(f"refined pattern does not compile: {e}")
        return errs   # other checks need a compiled regex

    # G3: capture-group arity (must preserve the group {extracts}.g references)
    if extracts:
        for key, spec in extracts.items():
            if isinstance(spec, dict) and "g" in spec:
                g = spec["g"]
                if not isinstance(g, int) or g < 1 or g > cre.groups:
                    errs.append(
                        f"extracts.{key}.g={g} but refined pattern has "
                        f"{cre.groups} capture group(s). Refining must "
                        "preserve the group index used by extracts."
                    )

    # G1: monotonic coverage on originally-cited spans (the floor)
    for i, txt in enumerate(original_cited_texts):
        if not cre.search(txt):
            errs.append(
                "GUARDRAIL VIOLATION (regression): refined pattern no "
                f"longer matches original cited span #{i}. Widening must "
                "be a SUPERSET of the original behaviour. Lost match on "
                f"text (first 200 chars, repr): {txt[:200]!r}"
            )

    # G2: counter-examples must match
    for i, txt in enumerate(counter_example_texts):
        if not cre.search(txt):
            errs.append(
                "GUARDRAIL VIOLATION (counter unmatched): refined pattern "
                f"still does not match counter-example #{i}. text "
                f"(first 200 chars, repr): {txt[:200]!r}"
            )

    return errs


# ---------------------------------------------------------------------------
# Loop
# ---------------------------------------------------------------------------

def _build_initial_task(rule: dict, counters: list[CounterExample],
                        pattern_history: list[dict] | None) -> str:
    return json.dumps({
        "existing_rule_pattern": rule.get("pattern"),
        "existing_rule_extracts": rule.get("extracts"),
        "original_cited_spans_preview": [
            {"file_path": c.get("file_path"),
             "line_start": c.get("line_start"),
             "line_end": c.get("line_end"),
             "text_first_300": (c.get("_text_preview") or "")[:300]}
            for c in (rule.get("source") or {}).get("citations") or []
        ],
        "counter_examples": [c.to_payload() for c in counters],
        "pattern_history": pattern_history or [],
        "instruction": (
            "Widen the regex so it matches ALL of the original cited "
            "spans AND ALL of the counter-examples. Emit the refine JSON."
        ),
    }, ensure_ascii=False, indent=2)


def refine_rule(
    client: GeminiClient,
    rule: dict,
    original_cited_texts: list[str],
    counter_examples: list[CounterExample],
    *,
    pattern_history: list[dict] | None = None,
    verbose: bool = False,
) -> dict:
    """Run the refiner loop.

    Returns either:
      - the original rule dict with `pattern` updated + `_drafter_meta`
        augmented with `refined_from`, `widening_summary`, `signal_shape`;
      - or {"_aborted": "<reason>"} if no acceptable widening was found.
    """
    original_pattern = rule.get("pattern") or ""
    counter_texts = [c.text for c in counter_examples]
    history = list(pattern_history or [])

    msgs: list[Message] = [Message(
        role="user",
        text=_build_initial_task(rule, counter_examples, history),
    )]

    for turn in range(MAX_TURNS):
        raw = client.generate(msgs, system=REFINER_SYSTEM_PROMPT)
        if verbose:
            print(f"--- refiner turn {turn} ---\n{raw[:400]}\n", file=sys.stderr)
        try:
            step = json.loads(raw)
        except json.JSONDecodeError as e:
            msgs.append(Message("model", raw))
            msgs.append(Message("user",
                f"Your last output was not valid JSON ({e}). Emit ONE "
                "JSON object. JSON only."))
            continue
        msgs.append(Message("model", raw))

        if step.get("tool") != "refine":
            msgs.append(Message("user",
                "Wrong tool name. Use 'refine'. Emit one JSON object."))
            continue

        new_rule = step.get("rule")
        if new_rule is None:
            reason = step.get("_abort_reason", "refiner aborted without reason")
            return {"_aborted": reason}

        new_pattern = new_rule.get("pattern") or ""
        errs = _verify_refiner_guardrails(
            new_pattern=new_pattern,
            original_pattern=original_pattern,
            original_cited_texts=original_cited_texts,
            counter_example_texts=counter_texts,
            extracts=rule.get("extracts"),
        )
        if not errs:
            # Update the existing rule structurally; do NOT replace it
            # wholesale (preserve id, section, kind, extracts, citations,
            # confidence). Only the pattern + drafter meta changes.
            updated = dict(rule)
            updated["pattern"] = new_pattern
            meta = dict(updated.get("_drafter_meta") or {})
            meta.update(new_rule.get("_drafter_meta") or {})
            meta.setdefault("pattern_history", history)
            updated["_drafter_meta"] = meta
            return updated

        # Append the failed attempt to history so the next turn can see it.
        history.append({
            "pattern": new_pattern,
            "failed_because": "; ".join(errs)[:300],
        })
        if verbose:
            print(f"refiner guardrails failed:\n  - "
                  + "\n  - ".join(errs[:3]), file=sys.stderr)
        msgs.append(Message("user",
            "Your proposed pattern failed structural guardrails:\n"
            + "\n".join(f"  - {e}" for e in errs)
            + "\n\nRevise. Remember: monotonic coverage (must still match "
              "the original cited spans), and the capture group used by "
              "extracts must be preserved."))

    return {"_aborted": f"refiner exhausted MAX_TURNS={MAX_TURNS}"}
