"""Lab/research dashboard: catalog + inspect + mine + stats.

Run:
    streamlit run lab/research/dashboard/app.py

Covers the rule-mining workflow under `lab/research/`:
- Catalog every config.yaml + version_rules.json on disk.
- Inspect a library/plugin's rules, sample contexts, config.
- Launch mine_paths.py (single config) or mine_all_plugins.py (bulk).
- View aggregate stats (regex family distribution, validation depth, etc).
- View Font Awesome CVE-driven detection rules (rules.json + cves.json).
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import backtest  # noqa: E402
import loader  # noqa: E402


RESEARCH_ROOT = loader.RESEARCH_ROOT
MINE_PATHS = RESEARCH_ROOT / "mine_paths.py"
MINE_ALL = RESEARCH_ROOT / "mine_all_plugins.py"

# repo root = lab/research/dashboard -> lab/research -> lab -> DATN2
_REPO_ROOT = RESEARCH_ROOT.parent.parent
DEFAULT_SCAN_JSONL = _REPO_ROOT / "data" / "scan_results_dev.jsonl"


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def _catalog_rows(libs: list[loader.Library]) -> list[dict]:
    rows = []
    for lib in libs:
        rows.append({
            "kind": lib.kind,
            "slug": lib.slug,
            "product": lib.name,
            "primary": lib.primary,
            "n_cross": len(lib.cross),
            "rules": lib.rule_count,
            "tagged": ("" if lib.tagged is None else ("yes" if lib.tagged else "no")),
            "exit": ("" if lib.exit_code is None else str(lib.exit_code)),
            "dir": str(lib.dir.relative_to(RESEARCH_ROOT)),
        })
    return rows


def render_catalog_tab(libs: list[loader.Library]) -> None:
    st.subheader("Library / plugin catalog")
    st.caption(f"Scanned: `{RESEARCH_ROOT}`")

    if not libs:
        st.info("No version_rules.json files found. Try the Mine tab.")
        return

    df = pd.DataFrame(_catalog_rows(libs))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Libraries", int((df["kind"] == "library").sum()))
    c2.metric("Plugins", int((df["kind"] == "plugin").sum()))
    c3.metric("Total rules", int(df["rules"].sum()))
    c4.metric("Zero-rule entries", int((df["rules"] == 0).sum()))

    st.dataframe(df, use_container_width=True, height=520)

    # Rule-count histogram
    st.markdown("#### Rule count per entry")
    counts = df.groupby("slug")["rules"].sum().sort_values(ascending=False)
    st.bar_chart(counts, height=260)


# ---------------------------------------------------------------------------
# Inspect
# ---------------------------------------------------------------------------

def render_inspect_tab(libs: list[loader.Library]) -> None:
    st.subheader("Inspect rules")

    if not libs:
        st.info("No libraries to inspect.")
        return

    slugs = [lib.slug for lib in libs]
    chosen = st.selectbox("Library / plugin", slugs, index=0)
    lib = next(l for l in libs if l.slug == chosen)

    st.markdown(f"**{lib.name}** - kind: `{lib.kind}` - "
                f"primary: `{lib.primary or '?'}` - "
                f"cross: `{', '.join(lib.cross) or '(none)'}` - "
                f"rules: **{lib.rule_count}**")
    st.caption(f"Dir: `{lib.dir}`")

    if lib.summary:
        with st.expander("Summary row (from plugins/_summary.json)"):
            st.json(lib.summary)

    if lib.config:
        with st.expander("config.yaml"):
            st.code(yaml.safe_dump(lib.config, sort_keys=False), language="yaml")

    if lib.rule_count == 0:
        st.warning("No rules in version_rules.json.")
        return

    st.markdown("#### Rules")
    st.dataframe(pd.DataFrame(lib.rule_rows), use_container_width=True, height=320)

    # Per-rule detail (path + regex + sample contexts)
    st.markdown("#### Detail")
    for i, r in enumerate(lib.rules.get("rules", []) or []):
        with st.expander(f"[{i}] {r.get('path', '?')}  --  {r.get('regex_family', '?')}"):
            st.code(r.get("regex", ""), language="regex")
            st.write("Validated versions:", ", ".join(r.get("validated_versions", []) or []) or "(none)")
            samples = r.get("sample_context", {}) or {}
            if samples:
                st.markdown("**Sample context**")
                for ver, ctx in samples.items():
                    st.markdown(f"`{ver}`")
                    st.code(ctx)


# ---------------------------------------------------------------------------
# Mine (launch tools)
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str, str, float]:
    t0 = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr, time.monotonic() - t0


def render_mine_tab(libs: list[loader.Library]) -> None:
    st.subheader("Mine new rules")

    mode = st.radio(
        "Mode",
        ["Single config (mine_paths.py)", "All plugins (mine_all_plugins.py)"],
        horizontal=True,
    )

    if mode.startswith("Single"):
        # Discover all configs (catalog libs + any orphan config without rules yet).
        all_configs = sorted(p for p in RESEARCH_ROOT.rglob("config.yaml")
                              if p.parent.name != "dashboard")
        if not all_configs:
            st.warning("No config.yaml files found under lab/research/.")
            return

        rel = [str(p.relative_to(RESEARCH_ROOT)) for p in all_configs]
        chosen_rel = st.selectbox("Config", rel, index=0)
        cfg_path = RESEARCH_ROOT / chosen_rel

        c1, c2 = st.columns(2)
        with c1:
            override_primary = st.text_input("Override --primary (optional)", value="")
        with c2:
            override_cross = st.text_input("Override --cross (comma-sep, optional)", value="")

        timeout_s = st.number_input("Timeout (seconds)", 30, 60 * 60, 600)

        if st.button("Run mine_paths.py", type="primary"):
            cmd = [sys.executable, str(MINE_PATHS), "--config", str(cfg_path)]
            if override_primary.strip():
                cmd += ["--primary", override_primary.strip()]
            if override_cross.strip():
                cmd += ["--cross", override_cross.strip()]
            st.code(" ".join(shlex.quote(c) for c in cmd), language="bash")

            status = st.status("Mining...", expanded=True)
            try:
                rc, out, err, elapsed = _run(cmd, RESEARCH_ROOT, timeout_s)
            except subprocess.TimeoutExpired:
                status.update(label="Timed out", state="error")
                return

            state = "complete" if rc == 0 else "error"
            status.update(label=f"Exit {rc} in {elapsed:.1f}s", state=state)
            if out:
                st.markdown("**stdout**")
                st.code(out)
            if err:
                st.markdown("**stderr**")
                st.code(err)

            # Show updated rules file if it exists.
            rules_path = cfg_path.parent / "version_rules.json"
            if rules_path.exists():
                try:
                    data = json.loads(rules_path.read_text(encoding="utf-8"))
                    st.success(f"{rules_path.name}: {len(data.get('rules', []))} rule(s)")
                    st.json(data, expanded=False)
                except json.JSONDecodeError:
                    st.warning("version_rules.json exists but failed to parse")

    else:
        st.write("Runs `mine_all_plugins.py` over every active slug in slugs.json.")
        timeout_s = st.number_input("Timeout (seconds)", 60, 60 * 60 * 4, 60 * 30)
        if st.button("Run mine_all_plugins.py", type="primary"):
            cmd = [sys.executable, str(MINE_ALL)]
            st.code(" ".join(shlex.quote(c) for c in cmd), language="bash")

            status = st.status("Running bulk miner...", expanded=True)
            try:
                rc, out, err, elapsed = _run(cmd, RESEARCH_ROOT, timeout_s)
            except subprocess.TimeoutExpired:
                status.update(label="Timed out", state="error")
                return

            state = "complete" if rc == 0 else "error"
            status.update(label=f"Exit {rc} in {elapsed:.1f}s", state=state)
            if out:
                with st.expander("stdout", expanded=False):
                    st.code(out)
            if err:
                with st.expander("stderr", expanded=False):
                    st.code(err)

            summary = loader.load_summary()
            if summary:
                st.markdown("#### Updated _summary.json")
                df = pd.DataFrame([
                    {
                        "slug": s,
                        "product": row.get("product", ""),
                        "primary": row.get("primary", ""),
                        "cross": len(row.get("cross", []) or []),
                        "tagged": row.get("tagged"),
                        "rules": row.get("rule_count", 0),
                        "exit": row.get("exit_code"),
                    }
                    for s, row in summary.items()
                ])
                st.dataframe(df, use_container_width=True)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def render_stats_tab(libs: list[loader.Library]) -> None:
    st.subheader("Mining stats")

    if not libs:
        st.info("No libraries.")
        return

    s = loader.compute_stats(libs)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Libraries", s.n_libraries)
    c2.metric("Plugins", s.n_plugins)
    c3.metric("Rules", s.total_rules)
    c4.metric("Zero-rule entries", len(s.libs_with_zero_rules))

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Regex family distribution")
        if s.regex_family_counts:
            df = pd.DataFrame(s.regex_family_counts.most_common(),
                              columns=["regex_family", "count"])
            st.bar_chart(df, x="regex_family", y="count", height=320)
            st.dataframe(df, use_container_width=True)
        else:
            st.caption("(no rules)")

    with col2:
        st.markdown("#### Path extension distribution")
        if s.path_ext_counts:
            df = pd.DataFrame(s.path_ext_counts.most_common(),
                              columns=["extension", "count"])
            st.bar_chart(df, x="extension", y="count", height=320)
            st.dataframe(df, use_container_width=True)
        else:
            st.caption("(no rules)")

    st.markdown("#### Validation depth (#cross versions confirming a rule)")
    if s.n_validated_counts:
        df = pd.DataFrame(
            sorted(s.n_validated_counts.items()),
            columns=["n_validated_versions", "rule_count"],
        )
        st.bar_chart(df, x="n_validated_versions", y="rule_count", height=240)
    else:
        st.caption("(no rules)")

    if s.libs_with_zero_rules:
        st.markdown("#### Entries with zero rules")
        st.code("\n".join(s.libs_with_zero_rules))

    if s.libs_untagged:
        st.markdown("#### Entries with no SVN tags (trunk-only)")
        st.code("\n".join(s.libs_untagged))

    if s.libs_failed:
        st.markdown("#### Entries that exited non-zero")
        st.dataframe(pd.DataFrame(s.libs_failed, columns=["slug", "exit_code"]))


# ---------------------------------------------------------------------------
# CVE rules (FA-specific)
# ---------------------------------------------------------------------------

def render_cve_tab() -> None:
    st.subheader("Font Awesome - CVE-driven detection rules")
    st.caption(f"Source: `{loader.FA_DIR}`")

    rules = loader.load_fa_rules()
    cves = loader.load_fa_cves()

    if not rules and not cves:
        st.info("No fontawesome/rules.json or cves.json present.")
        return

    c1, c2 = st.columns(2)
    c1.metric("Detection rules", rules.get("rule_count", len(rules.get("rules", []))))
    c2.metric("CVEs in catalog", cves.get("total", len(cves.get("cves", []))))

    rule_rows = []
    for r in rules.get("rules", []) or []:
        rule_rows.append({
            "slug": r.get("slug", ""),
            "product": r.get("product", ""),
            "wp_status": r.get("wp_status", ""),
            "paths": ", ".join(r.get("paths", []) or []),
            "version_regex": r.get("version_regex", ""),
            "n_cves": len(r.get("cves", []) or []),
        })
    if rule_rows:
        st.markdown("#### Plugin detection rules")
        st.dataframe(pd.DataFrame(rule_rows), use_container_width=True, height=360)

    # CVEs table
    cve_rows = []
    for c in cves.get("cves", []) or []:
        cve_rows.append({
            "cve": c.get("cve", ""),
            "cvss": c.get("cvss", ""),
            "vuln_type": c.get("vuln_type", ""),
            "product": c.get("product", ""),
            "affected_versions": c.get("affected_versions", ""),
            "published": c.get("published", ""),
        })
    if cve_rows:
        st.markdown("#### CVEs")
        st.dataframe(pd.DataFrame(cve_rows), use_container_width=True, height=360)

    # Per-rule expand
    if rules.get("rules"):
        st.markdown("#### Detail")
        for r in rules.get("rules", []) or []:
            with st.expander(f"{r.get('slug', '?')}  --  {r.get('product', '')}"):
                st.write("**WP status:**", r.get("wp_status", ""))
                if r.get("wp_notes"):
                    st.caption(r.get("wp_notes"))
                st.write("**Paths:**", r.get("paths", []))
                st.write("**Version regex:**")
                st.code(r.get("version_regex", ""), language="regex")
                if r.get("cves"):
                    st.write("**CVEs:**")
                    st.dataframe(pd.DataFrame(r["cves"]), use_container_width=True)


# ---------------------------------------------------------------------------
# New tech (create a new lab/research/<slug>/config.yaml)
# ---------------------------------------------------------------------------

# URL templates mirrored from mine_paths.py and mine_all_plugins.py so the
# dashboard preset matches what the miners themselves use.
_GITHUB_ARCHIVE = "https://codeload.github.com/{repo}/zip/refs/tags/{tag}"
_GITHUB_RAW = "https://raw.githubusercontent.com/{repo}/{tag}/{path}"
_WP_ARCHIVE = "https://downloads.wordpress.org/plugin/{slug}.{tag}.zip"
_WP_RAW = "https://plugins.svn.wordpress.org/{slug}/tags/{tag}/{path}"

_GITHUB_DEFAULT_PATHS = [
    "dist/*.js",
    "dist/*.min.js",
    "*.js",
    "package.json",
]
_GITHUB_DEFAULT_REGEX_BANK = [
    {"label": 'json: "version": "X.Y.Z"',
     "pattern": r'"version"\s*:\s*"([0-9][^"]*)"'},
    {"label": "banner comment: <Name> vX.Y.Z",
     "pattern": r"v([0-9]+\.[0-9]+\.[0-9]+[\w.\-]*)"},
]

_WP_DEFAULT_PATHS = [
    "readme.txt",
    "*.php",
    "**/*.php",
    "block.json",
    "package.json",
]
_WP_DEFAULT_REGEX_BANK = [
    {"label": "wp plugin readme: Stable tag: X.Y.Z",
     "pattern": r"(?im)^Stable\s*tag\s*:\s*([0-9][\w.\-]*)"},
    {"label": "php header: Version: X.Y.Z",
     "pattern": r"(?im)^\s*\*?\s*Version\s*:\s*([0-9][\w.\-]*)"},
    {"label": 'json: "version": "X.Y.Z"',
     "pattern": r'"version"\s*:\s*"([0-9][^"]*)"'},
    {"label": "php define: PLUGIN_VERSION-style constant",
     "pattern": r"""define\s*\(\s*['"][A-Z][A-Z0-9_]*VERSION['"]\s*,\s*['"]([0-9][\w.\-]*)['"]"""},
]


def _safe_slug(s: str) -> str | None:
    """Allow lowercase alphanumeric + dash. Return None if invalid."""
    import re
    s = s.strip().lower()
    if not s:
        return None
    if not re.fullmatch(r"[a-z0-9][a-z0-9\-]*", s):
        return None
    if s in {"dashboard", "plugins", "__pycache__", "out"}:
        return None
    return s


def _build_config_dict(preset: str, opts: dict) -> dict:
    """Assemble the YAML dict in a stable key order matching the example
    configs (so manual diffs read cleanly)."""
    cfg: dict = {}
    # Free vars first (repo / slug / etc) since the example configs lead with them.
    if preset == "github":
        cfg["repo"] = opts["repo"]
    elif preset == "wp-plugin":
        cfg["slug"] = opts["slug"]
        cfg["archive_url"] = _WP_ARCHIVE
        cfg["raw_url"] = _WP_RAW
    else:
        # Custom: free vars come from a raw key=value text blob.
        for k, v in opts.get("free_vars", {}).items():
            cfg[k] = v
        if opts.get("archive_url"):
            cfg["archive_url"] = opts["archive_url"]
        if opts.get("raw_url"):
            cfg["raw_url"] = opts["raw_url"]

    cfg["primary"] = opts["primary"]
    cfg["cross"] = opts["cross"]
    cfg["include_paths"] = opts["include_paths"]
    cfg["regex_bank"] = opts["regex_bank"]
    return cfg


def _parse_free_vars(blob: str) -> dict[str, str]:
    """Parse 'key: value' or 'key=value' lines into a dict."""
    out: dict[str, str] = {}
    for line in blob.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
        elif "=" in line:
            k, v = line.split("=", 1)
        else:
            continue
        out[k.strip()] = v.strip().strip("'\"")
    return out


def render_new_tech_tab() -> None:
    st.subheader("Create config for a new tech")
    st.caption(
        "Writes `lab/research/<slug>/config.yaml`. The mining engine is "
        "library-agnostic - once saved, run it from the Mine tab (or use "
        "the button below). See CLAUDE.md - 'Adding a new library'."
    )

    # --- Identity --------------------------------------------------------
    col1, col2 = st.columns(2)
    with col1:
        slug_raw = st.text_input(
            "Slug (directory name)",
            value="",
            help="Lowercase letters, digits, dashes. Becomes lab/research/<slug>/.",
        )
    with col2:
        preset = st.radio(
            "Source preset",
            ["github", "wp-plugin", "custom"],
            index=0,
            horizontal=True,
            help=(
                "github = github repo via codeload + raw. "
                "wp-plugin = wordpress.org SVN tags. "
                "custom = bring your own URL templates and free vars."
            ),
        )

    # --- Source-specific inputs -----------------------------------------
    repo = wp_slug = archive_url = raw_url = ""
    free_vars_blob = ""
    if preset == "github":
        repo = st.text_input(
            "GitHub repo (owner/name)", value="",
            help="Example: jquery/jquery. Becomes {repo} in the URL templates.",
        )
    elif preset == "wp-plugin":
        wp_slug = st.text_input(
            "WordPress plugin slug", value="",
            help=(
                "The /wp-content/plugins/<slug>/ path component. "
                "Defaults to the directory slug above if left blank."
            ),
        )
    else:
        st.markdown("**Free variables** (one `key: value` per line; available as `{key}` in URL templates)")
        free_vars_blob = st.text_area("Free vars", value="", height=100, key="free_vars_blob")
        archive_url = st.text_input(
            "archive_url template", value=_GITHUB_ARCHIVE,
            help="Must contain {tag}; other {keys} resolve from free vars.",
        )
        raw_url = st.text_input(
            "raw_url template", value=_GITHUB_RAW,
            help="Must contain {tag} and {path}.",
        )

    # --- Versions --------------------------------------------------------
    v1, v2 = st.columns(2)
    with v1:
        primary = st.text_input(
            "Primary version", value="",
            help="The version that gets downloaded in full and scanned for literal occurrences.",
        )
    with v2:
        cross_raw = st.text_input(
            "Cross versions (comma-separated)", value="",
            help="Older versions raw-fetched per candidate path for cross-validation. Optional.",
        )

    # --- Path globs ------------------------------------------------------
    defaults_paths = _WP_DEFAULT_PATHS if preset == "wp-plugin" else _GITHUB_DEFAULT_PATHS
    include_paths_raw = st.text_area(
        "include_paths (one glob per line)",
        value="\n".join(defaults_paths),
        height=140,
        help=(
            "PurePosixPath.match globs. Left-anchored by default; leading "
            "`**/` matches any depth. Example: `css/*.css`, `**/_variables.scss`."
        ),
    )

    # --- Regex bank ------------------------------------------------------
    st.markdown("**Regex bank** (ordered; first whose pattern matches the +-60 char context wins)")
    defaults_bank = _WP_DEFAULT_REGEX_BANK if preset == "wp-plugin" else _GITHUB_DEFAULT_REGEX_BANK
    regex_df = st.data_editor(
        pd.DataFrame(defaults_bank),
        num_rows="dynamic",
        use_container_width=True,
        key=f"regex_bank_editor_{preset}",  # reset when preset toggles
        column_config={
            "label": st.column_config.TextColumn("label", help="Short identifier shown in mined rules"),
            "pattern": st.column_config.TextColumn(
                "pattern",
                help="Python regex with ONE capture group around the version digits",
            ),
        },
    )

    # --- Assemble + preview ---------------------------------------------
    slug = _safe_slug(slug_raw)
    if slug_raw and not slug:
        st.warning(
            "Invalid slug. Use lowercase letters, digits, and dashes only "
            "(reserved: dashboard, plugins, __pycache__, out)."
        )

    cross = [v.strip() for v in cross_raw.split(",") if v.strip()]
    include_paths = [p.strip() for p in include_paths_raw.splitlines() if p.strip()]

    regex_bank: list[dict[str, str]] = []
    for _, row in regex_df.iterrows():
        label = (row.get("label") or "").strip() if isinstance(row.get("label"), str) else ""
        pattern = (row.get("pattern") or "").strip() if isinstance(row.get("pattern"), str) else ""
        if label and pattern:
            regex_bank.append({"label": label, "pattern": pattern})

    # Validation errors (collected, surfaced on submit)
    errors: list[str] = []
    if not slug:
        errors.append("Slug is required and must be valid.")
    if not primary.strip():
        errors.append("Primary version is required.")
    if not include_paths:
        errors.append("At least one include_paths entry is required.")
    if not regex_bank:
        errors.append("At least one regex_bank entry (label + pattern) is required.")
    if preset == "github" and not repo.strip():
        errors.append("GitHub repo (owner/name) is required.")
    if preset == "wp-plugin" and not (wp_slug.strip() or slug):
        errors.append("WordPress plugin slug is required.")

    opts = dict(
        repo=repo.strip(),
        slug=(wp_slug.strip() or slug or ""),
        free_vars=_parse_free_vars(free_vars_blob),
        archive_url=archive_url.strip(),
        raw_url=raw_url.strip(),
        primary=primary.strip(),
        cross=cross,
        include_paths=include_paths,
        regex_bank=regex_bank,
    )

    cfg_dict: dict | None = None
    if not errors:
        cfg_dict = _build_config_dict(preset, opts)
        with st.expander("Preview config.yaml", expanded=True):
            st.code(
                yaml.safe_dump(cfg_dict, sort_keys=False, allow_unicode=True),
                language="yaml",
            )

    out_dir = RESEARCH_ROOT / (slug or "<slug>")
    out_path = out_dir / "config.yaml"
    will_overwrite = out_path.exists() if slug else False

    if will_overwrite:
        st.warning(f"`{out_path.relative_to(RESEARCH_ROOT)}` already exists; saving will overwrite.")

    # --- Action buttons -------------------------------------------------
    b1, b2 = st.columns(2)
    save_clicked = b1.button("Save config", type="primary", disabled=bool(errors))
    save_and_mine = b2.button("Save and mine", disabled=bool(errors))

    if errors:
        for e in errors:
            st.error(e)

    if save_clicked or save_and_mine:
        assert cfg_dict is not None
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                yaml.safe_dump(cfg_dict, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
        except OSError as e:
            st.error(f"Failed to write {out_path}: {e}")
            return

        st.success(f"Wrote {out_path}")
        st.cache_data.clear()  # so Catalog/Inspect pick up the new entry

        if save_and_mine:
            cmd = [sys.executable, str(MINE_PATHS), "--config", str(out_path)]
            st.code(" ".join(shlex.quote(c) for c in cmd), language="bash")
            status = st.status("Mining...", expanded=True)
            try:
                rc, out, err, elapsed = _run(cmd, RESEARCH_ROOT, timeout=600)
            except subprocess.TimeoutExpired:
                status.update(label="Timed out (10m)", state="error")
                return
            state = "complete" if rc == 0 else "error"
            status.update(label=f"Exit {rc} in {elapsed:.1f}s", state=state)
            if out:
                st.markdown("**stdout**")
                st.code(out)
            if err:
                st.markdown("**stderr**")
                st.code(err)
            rules_path = out_dir / "version_rules.json"
            if rules_path.exists():
                try:
                    data = json.loads(rules_path.read_text(encoding="utf-8"))
                    st.success(f"{rules_path.name}: {len(data.get('rules', []))} rule(s)")
                    st.json(data, expanded=False)
                except json.JSONDecodeError:
                    st.warning("version_rules.json exists but failed to parse")


# ---------------------------------------------------------------------------
# Back-test mined rules against scanner results
# ---------------------------------------------------------------------------

def render_backtest_tab(libs: list[loader.Library]) -> None:
    st.subheader("Back-test lab rules against scan results")
    st.caption(
        "For each detected tech in scan_results.jsonl, refetch the **exact "
        "evidence URLs the scanner already recorded** for that tech and run "
        "every matching lab rule's regex against the body. URLs the scanner "
        "never saw the tech at are not probed. Detections without evidence "
        "URLs are skipped."
    )
    # Fetch-strategy picker + status banner.
    avail = backtest.available_strategies()
    strategy_labels = []
    strategy_values = []
    for s in ("requests", "curl_cffi", "playwright"):
        if avail.get(s):
            mark = "" if s != backtest.DEFAULT_STRATEGY else " (recommended)"
            strategy_labels.append(f"{s}{mark}")
            strategy_values.append(s)
        else:
            strategy_labels.append(f"{s} (not installed)")
            strategy_values.append(s)
    default_idx = strategy_values.index(backtest.DEFAULT_STRATEGY) \
        if backtest.DEFAULT_STRATEGY in strategy_values else 0
    chosen_label = st.radio(
        "Fetch strategy",
        strategy_labels,
        index=default_idx,
        horizontal=True,
        help=(
            "requests: vanilla TCP/TLS, UA spoofing only. "
            "curl_cffi: replays Chrome 120's JA3/JA4 TLS fingerprint - "
            "bypasses basic Cloudflare Bot Score. "
            "playwright: real headless Chromium with stealth init script - "
            "defeats JS challenges and accumulates clearance cookies. "
            "Slow (~1-3s/URL, single-threaded) but works on Turnstile."
        ),
    )
    strategy = strategy_values[strategy_labels.index(chosen_label)]
    if not avail.get(strategy):
        st.error(
            f"`{strategy}` is selected but its backing library is not installed. "
            f"Falls back to `requests` at runtime. "
            f"Install: pip install {('curl_cffi' if strategy == 'curl_cffi' else 'playwright && python -m playwright install chromium')}."
        )
    else:
        st.success(f"Fetch strategy: {backtest.http_client_info(strategy)}")

    # --- Inputs ---------------------------------------------------------
    scan_path_str = st.text_input(
        "Scan results JSONL",
        value=str(DEFAULT_SCAN_JSONL),
        help="UTF-16 BOM is auto-detected (matches the scanner's Windows default).",
    )
    scan_path = Path(scan_path_str)

    c1, c2, c3 = st.columns(3)
    with c1:
        only_unversioned = st.checkbox(
            "Only techs without a version", value=True,
            help="Skip techs the scanner already versioned (retire.js, Wappalyzer, version probes).",
        )
        use_pattern_pool = st.checkbox(
            "Apply universal pattern pool", value=True,
            help=(
                "Apply EVERY unique regex mined anywhere in the lab to each "
                "back-test URL, in addition to the per-tech rules. Patterns "
                "like `Stable tag: X.Y.Z` are generic - the lab just happens "
                "to mine them per-plugin. This closes the 'lab didn't mine "
                "this pattern for this plugin' gap. Origin prefixed as "
                "`pool:<slug>` in results so you can see where it came from."
            ),
        )
        cross_host_walk = st.checkbox(
            "Cross-host HTML link walk (extra pass)", value=True,
            help=(
                "Fetches each FA-flagged target's homepage and pulls cross-host "
                "`<link href>` / `<script src>` URLs that contain a matched "
                "lib's name (e.g. `use.fontawesome.com/releases/v6.6.0/...`), "
                "then applies the lab's URL patterns to those URLs. Closes the "
                "scanner-side gap where cross-host CSS asset URLs weren't "
                "recorded as evidence. Adds 1-2s per FA-flagged target."
            ),
        )
        max_urls = st.number_input(
            "Max unique URLs to fetch", 1, 100000, 500,
            help="Cap on UNIQUE HTTP fetches. Multiple lab rules against the "
                 "same URL share one fetch (regex match is free), so this is "
                 "the actual network cost. Raise if some scan-evidence URLs "
                 "are being silently dropped.",
        )
    with c2:
        concurrency = st.number_input("Concurrent fetches", 1, 50, 10)
        timeout = st.number_input("Per-request timeout (s)", 1, 60, 10)
    with c3:
        ua = st.text_input("User-Agent", value=backtest.DEFAULT_UA)
        verify_ssl = st.checkbox(
            "Verify SSL", value=False,
            help="Default OFF because real-world targets often have invalid/expired certs.",
        )

    # --- Anti-bot throttle ---------------------------------------------
    with st.expander("Anti-bot throttle (per-host delay + retry-on-block)", expanded=False):
        st.caption(
            "Per-host: only one request to a given host at a time, with a "
            "minimum gap + random jitter between consecutive requests to "
            "the same host. Requests to different hosts run fully in "
            "parallel. Block-page detection covers Cloudflare, Akamai, "
            "Sucuri, DataDome, Imperva, PerimeterX - a single retry fires "
            "after the backoff before the URL is reported as blocked."
        )
        d1, d2, d3 = st.columns(3)
        with d1:
            min_delay_ms = st.number_input(
                "Min delay per host (ms)", 0, 60000, 250, step=50,
                help="Crank up to 1000-3000ms for aggressive bot-managed targets.",
            )
        with d2:
            jitter_ms = st.number_input(
                "Random jitter (ms)", 0, 5000, 150, step=50,
                help="Adds U(0, jitter) ms on top of min delay so timing "
                     "doesn't look mechanical.",
            )
        with d3:
            retry_on_block = st.checkbox("Retry once on detected block", value=True)
            retry_backoff_ms = st.number_input(
                "Backoff before retry (ms)", 0, 60000, 2000, step=500,
            )

    # --- Preview (offline) ---------------------------------------------
    if not scan_path.exists():
        st.error(f"Scan results file not found: {scan_path}")
        return

    if st.button("Preview candidates (no fetch)"):
        try:
            cands: list = []
            seen_urls: set[str] = set()
            for c in backtest.iter_candidates(
                scan_path, libs,
                only_unversioned=only_unversioned,
                use_pattern_pool=use_pattern_pool,
            ):
                if c.url not in seen_urls:
                    if len(seen_urls) >= int(max_urls):
                        # New URL would exceed cap; stop entirely (rules for
                        # already-seen URLs would still be appended below, but
                        # those are bounded and cheap).
                        break
                    seen_urls.add(c.url)
                cands.append(c)
        except Exception as e:
            st.error(f"Failed to enumerate candidates: {e}")
            return

        st.session_state["_backtest_candidates"] = cands
        if not cands:
            st.warning(
                "No candidates. Either the scan file has no matching techs, "
                "no matching tech detections carry evidence URLs, or no lab "
                "rules exist for those tech names. Tech name matching is "
                "normalized (strip non-alnum, lowercase)."
            )
            return

        df = pd.DataFrame([c.to_row() for c in cands])
        unique_urls = df["url"].nunique() if not df.empty else 0
        st.success(
            f"{len(cands)} candidate(s) queued across {unique_urls} unique URL(s) "
            f"(URL cap = {int(max_urls)})."
        )
        st.dataframe(
            df[["target", "tech_name", "lib_slug", "rule_path", "regex_family", "url"]]
            .rename(columns={"regex_family": "regex_label"}),
            use_container_width=True, height=420,
        )

        # Coverage by tech
        cov = df.groupby("tech_name").size().reset_index(name="candidates").sort_values("candidates", ascending=False)
        st.markdown("#### Candidate count per tech")
        st.bar_chart(cov, x="tech_name", y="candidates", height=260)

    # --- Run (live fetch) ----------------------------------------------
    if st.button("Run back-test (live fetch)", type="primary"):
        try:
            cands: list = []
            seen_urls: set[str] = set()
            for c in backtest.iter_candidates(
                scan_path, libs,
                only_unversioned=only_unversioned,
                use_pattern_pool=use_pattern_pool,
            ):
                if c.url not in seen_urls:
                    if len(seen_urls) >= int(max_urls):
                        # New URL would exceed cap; stop entirely (rules for
                        # already-seen URLs would still be appended below, but
                        # those are bounded and cheap).
                        break
                    seen_urls.add(c.url)
                cands.append(c)
        except Exception as e:
            st.error(f"Failed to enumerate candidates: {e}")
            return

        if not cands:
            st.warning("No candidates - nothing to fetch.")
            return

        unique_urls = len({c.url for c in cands})
        st.info(
            f"{len(cands)} candidate(s) across {unique_urls} unique URL(s). "
            f"Fetching at concurrency={concurrency}, timeout={timeout}s..."
        )
        prog = st.progress(0.0)
        status = st.empty()

        def _on_progress(done: int, total: int) -> None:
            prog.progress(done / max(1, total))
            status.write(f"{done}/{total} URLs fetched")

        try:
            results = backtest.run_backtest(
                cands,
                concurrency=int(concurrency),
                timeout=float(timeout),
                ua=ua.strip() or backtest.DEFAULT_UA,
                verify_ssl=bool(verify_ssl),
                strategy=strategy,
                min_delay_s=float(min_delay_ms) / 1000.0,
                jitter_s=float(jitter_ms) / 1000.0,
                retry_on_block=bool(retry_on_block),
                retry_backoff_s=float(retry_backoff_ms) / 1000.0,
                progress_cb=_on_progress,
            )
        except Exception as e:
            st.error(f"Back-test crashed: {e}")
            return

        prog.empty()
        status.empty()

        # Optional second pass: walk cross-host <link href> from each
        # FA-flagged target's homepage and apply URL patterns to the
        # discovered references. Closes the scanner's same-host-only gap.
        if cross_host_walk:
            walk_status = st.status("Cross-host link walk...", expanded=False)
            walk_prog = st.progress(0.0)
            walk_msg = st.empty()

            def _on_walk(done: int, total: int) -> None:
                walk_prog.progress(done / max(1, total))
                walk_msg.write(f"{done}/{total} targets walked")

            try:
                walk_results = backtest.cross_host_walk_pass(
                    scan_path, libs,
                    strategy=strategy,
                    verify_ssl=bool(verify_ssl),
                    timeout=float(timeout),
                    ua=ua.strip() or backtest.DEFAULT_UA,
                    min_delay_s=float(min_delay_ms) / 1000.0,
                    jitter_s=float(jitter_ms) / 1000.0,
                    progress_cb=_on_walk,
                )
            except Exception as e:
                st.warning(f"Cross-host walk failed (continuing without it): {e}")
                walk_results = []
            results.extend(walk_results)
            walk_prog.empty()
            walk_msg.empty()
            walk_status.update(
                label=f"Cross-host walk: +{len(walk_results)} extractions",
                state="complete",
            )

        st.session_state["_backtest_results"] = results

        summary = backtest.summarize(results)
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Fetched", summary.total)
        m2.metric("Version extracted", summary.ok)
        m3.metric("No regex match", summary.no_match)
        m4.metric("4xx / 5xx", summary.http_4xx + summary.http_5xx)
        m5.metric("Blocked", summary.blocked,
                  help="Detected as Cloudflare/Akamai/Sucuri/etc challenge or block page (after retry)")
        m6.metric("Network errors", summary.error)
        st.write(
            f"**Distinct (target, tech) pairs now versioned via lab rules: "
            f"{summary.distinct_target_tech_versioned}**"
        )

        rows = [r.to_row() for r in results]
        df = pd.DataFrame(rows)

        st.markdown("#### Results")
        # Successful matches first - that's the headline output.
        ok_df = df[df["status"] == "ok"].copy()
        if not ok_df.empty:
            st.markdown("**Versions extracted**")
            st.dataframe(
                ok_df[["target", "tech", "extracted_version", "lib_slug",
                       "rule_path", "regex_family", "evidence_source", "url"]],
                use_container_width=True, height=320,
            )

        with st.expander(f"All {len(df)} results", expanded=False):
            st.dataframe(df, use_container_width=True, height=420)

        st.download_button(
            "Download results.csv",
            df.to_csv(index=False).encode("utf-8"),
            file_name="backtest_results.csv",
            mime="text/csv",
        )
        if not ok_df.empty:
            st.download_button(
                "Download versions.csv (matches only)",
                ok_df.to_csv(index=False).encode("utf-8"),
                file_name="backtest_versions.csv",
                mime="text/csv",
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="Lab/Research Dashboard", layout="wide")
    st.title("Lab / Research Dashboard")
    st.caption("Version-detection rule mining for libraries and WP plugins.")

    if st.sidebar.button("Reload from disk"):
        st.cache_data.clear()

    libs = _cached_load()

    tab_cat, tab_inspect, tab_new, tab_mine, tab_back, tab_stats, tab_cve = st.tabs(
        ["Catalog", "Inspect", "New tech", "Mine", "Back-test", "Stats", "CVE rules (FA)"]
    )

    with tab_cat:
        render_catalog_tab(libs)
    with tab_inspect:
        render_inspect_tab(libs)
    with tab_new:
        render_new_tech_tab()
    with tab_mine:
        render_mine_tab(libs)
    with tab_back:
        render_backtest_tab(libs)
    with tab_stats:
        render_stats_tab(libs)
    with tab_cve:
        render_cve_tab()


@st.cache_data
def _cached_load() -> list[loader.Library]:
    return loader.discover_libraries()


if __name__ == "__main__":
    main()
