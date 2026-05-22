"""Lab-side migration of fp/url_ver.py constants into lab.db.

Per CLAUDE.md architecture Phase A:
  Move _CDN_PATTERNS + _JS_LIB_MAP + _CDN_PKG_MAP + WP_PLUGIN_MAP from code
  into lab_url_patterns + lab_pkg_aliases tables so every detection gap is a
  one-row INSERT instead of a code commit + redeploy.

This module is the LAB SIDE of Phase A:
  * `schema.SCHEMA` — DDL for the two tables.
  * `seed.seed_from_constants()` — reads fp.url_ver constants, inserts rows.
  * `loader.load_*()` — returns the same Python types the in-code constants
    expose. Scanner can swap in a one-line "from url_ver_lab.loader import
    load_..." in the future; that refactor is NOT done here (per lab-scope
    directive). For now, the loader is exercised only by the parity test.

The seeded rows carry `origin='seeded:<constant-name>'` so a re-seed wipes
seed-origin rows without clobbering hand-curated additions.
"""
