"""Shared, tech-agnostic primitives for the lab research pipeline.

The lab has two pipelines that share data:

  - The Docker fixture lab (``lab/run.py``, ``lab/record.py``, ``lab/diff.py``)
    boots known-version containers and mines candidate version-extractors by
    diffing their responses. Independent of this package.

  - The research-cycle pipeline (``lab/research_cycle.py``, per-tech dirs
    under ``lab/research/<tech>/``) authors source-grounded detection rules
    and imports them into ``fingerprinter/lab.db``. THIS package holds the
    primitives that every tech research cycle reuses:

      - ``corpus``: JSONL reading with the LAB_ALLOW_TEST blind-test guard.
      - ``rules``:  ``lab_src_rules`` schema, import from rules_src.json,
                    load back into JSON shape, propagate to ``lab_url_patterns``.

The scanner-side reload paths (``fp.url_ver.reload``,
``fp.version_probes.reload``) are unaffected: this package writes to lab.db
the same rows they read.
"""

from lab.core.corpus import read_jsonl, guard_test_dataset
from lab.core.rules import (
    SCHEMA,
    RULE_SECTIONS,
    import_rules,
    load_rules_from_db,
    canonical_tech_name,
)

__all__ = [
    "read_jsonl",
    "guard_test_dataset",
    "SCHEMA",
    "RULE_SECTIONS",
    "import_rules",
    "load_rules_from_db",
    "canonical_tech_name",
]
