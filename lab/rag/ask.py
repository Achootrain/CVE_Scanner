"""Human CLI for ad-hoc queries against the rule-authoring index.

Inspect what the drafter would see for a given query, without running the
drafter loop. Useful when:

  - Debugging a "why didn't the agent find X?" case (is X indexed at all?).
  - Finding prior-tech analogues before starting a new tech.
  - Verifying the index includes the source you expect.

Usage:

    python -m lab.rag.ask source --tech bootstrap "version banner"
    python -m lab.rag.ask rules  "url path version"
    python -m lab.rag.ask research --tech jquery "css class prefix"
    python -m lab.rag.ask policy "tech detected version absent"

Each result line prints: score, source, tech, file_path:line_start-end, then
the first 240 chars of the chunk text (use --full to print the whole chunk).
"""
from __future__ import annotations

import argparse
import sys
from typing import Callable

from lab.rag import retrieval as rt


def _render(span: rt.Span, *, full: bool) -> str:
    head = (
        f"[{span.score:6.2f}] {span.source:8s} "
        f"{(span.tech or '-'):15s} {span.file_path}:{span.line_start}-{span.line_end}"
    )
    body = span.text if full else span.text.replace("\n", " ")[:240]
    return head + "\n    " + body


def _run(fn: Callable, args: argparse.Namespace) -> int:
    try:
        kwargs = {"k": args.k}
        if "tech" in fn.__code__.co_varnames:
            kwargs["tech"] = args.tech
        spans = fn(args.query, **kwargs)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    if not spans:
        print("(no results)")
        return 0
    for span in spans:
        print(_render(span, full=args.full))
        print()
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Query the rule-authoring RAG index.",
    )
    ap.add_argument("--full", action="store_true",
                    help="print full chunk text (default: 240-char preview)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_src = sub.add_parser("source", help="per-tech source code (REQUIRES --tech)")
    p_src.add_argument("query")
    p_src.add_argument("--tech", required=True)
    p_src.add_argument("-k", type=int, default=10)
    p_src.set_defaults(fn=rt.retrieve_source)

    p_r = sub.add_parser("rules", help="existing lab_src_rules rows (§9 gate corpus)")
    p_r.add_argument("query")
    p_r.add_argument("--tech")
    p_r.add_argument("-k", type=int, default=10)
    p_r.set_defaults(fn=rt.retrieve_rules)

    p_re = sub.add_parser("research", help="per-tech research artifacts (READMEs, rules_src.json)")
    p_re.add_argument("query")
    p_re.add_argument("--tech")
    p_re.add_argument("-k", type=int, default=5)
    p_re.set_defaults(fn=rt.retrieve_research)

    p_p = sub.add_parser("policy", help="CLAUDE.md sections")
    p_p.add_argument("query")
    p_p.add_argument("-k", type=int, default=3)
    p_p.set_defaults(fn=rt.retrieve_policy, tech=None)

    args = ap.parse_args(argv)
    return _run(args.fn, args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
