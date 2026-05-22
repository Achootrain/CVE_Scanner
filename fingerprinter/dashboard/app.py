"""Fingerprinter dashboard: Scan + Analyze + Report.

Run:
    streamlit run fingerprinter/dashboard/app.py

Tabs:
- Scan:     Launch `fp pipeline <target>` from the browser, view JSON output,
            optionally append to scan_results.jsonl.
- Analyze:  Aggregate charts/tables over a scan_results.jsonl file.
- Report:   Export the analysis as CSV / Markdown.
"""

from __future__ import annotations

import io
import json
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd
import streamlit as st

# Make analyzer.py importable when launched as a script.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import analyzer  # noqa: E402


REPO_ROOT = _HERE.parent  # fingerprinter/
DEFAULT_JSONL = REPO_ROOT / "scan_results.jsonl"


# ---------------------------------------------------------------------------
# Scan tab
# ---------------------------------------------------------------------------

def _build_pipeline_cmd(targets: list[str], files: list[str], opts: dict) -> list[str]:
    cmd = [sys.executable, "-m", "fp.cli", "pipeline", *targets, "--json"]

    for fp in files:
        cmd += ["--file", fp]

    # UA
    if opts.get("ua"):
        cmd += ["--ua", opts["ua"]]

    # Crawl / parallelism
    if opts.get("depth"):
        cmd += ["--depth", str(opts["depth"])]
    if opts.get("parallel"):
        cmd += ["--parallel", str(opts["parallel"])]
    if opts.get("concurrency"):
        cmd += ["--concurrency", str(opts["concurrency"])]
    if opts.get("bulk"):
        cmd += ["--bulk"]
    if opts.get("verify_ssl"):
        cmd += ["--verify-ssl"]
    if opts.get("use_cloak"):
        cmd += ["--use-cloak"]

    # Source toggles (all default ON in CLI)
    if not opts.get("katana", True):
        cmd += ["--no-katana"]
    if not opts.get("version_probes", True):
        cmd += ["--no-version-probes"]
    if not opts.get("cross_page", True):
        cmd += ["--no-cross-page"]
    if not opts.get("extract_bodies", True):
        cmd += ["--no-extract-bodies"]
    if not opts.get("extract_html", True):
        cmd += ["--no-extract-html"]
    if not opts.get("backend_probe", True):
        cmd += ["--no-backend-probe"]
    if not opts.get("jsextract", True):
        cmd += ["--no-jsextract"]

    # DB / cache paths -- only emit when user overrode the default,
    # so the CLI's own default-handling (and "skip if missing") still applies.
    if opts.get("cache"):
        cmd += ["--cache", opts["cache"]]
    if opts.get("db"):
        cmd += ["--db", opts["db"]]
    if opts.get("wap_db"):
        cmd += ["--wap-db", opts["wap_db"]]
    if opts.get("retire_db"):
        cmd += ["--retire-db", opts["retire_db"]]
    if opts.get("ww_db"):
        cmd += ["--ww-db", opts["ww_db"]]

    # Timeouts & budgets -- only emit when changed from CLI defaults to keep
    # the rendered command line short.
    _DEFAULTS = {
        "timeout": 10, "scan_timeout": 90, "katana_timeout": 60,
        "vp_timeout": 30, "cross_page_timeout": 120,
        "max_katana_urls": 500, "max_cross_page_urls": 30,
    }
    _FLAGS = {
        "timeout": "--timeout", "scan_timeout": "--scan-timeout",
        "katana_timeout": "--katana-timeout", "vp_timeout": "--vp-timeout",
        "cross_page_timeout": "--cross-page-timeout",
        "max_katana_urls": "--max-katana-urls",
        "max_cross_page_urls": "--max-cross-page-urls",
    }
    for k, flag in _FLAGS.items():
        v = opts.get(k)
        if v is not None and v != _DEFAULTS[k]:
            cmd += [flag, str(v)]

    cmd += ["--quiet"]  # we render our own status; stderr stays for errors
    return cmd


def _cleanup_scan_state(run_state: dict) -> None:
    """Close pipe-to-temp-file handles and remove the temp files.

    On Windows, Popen duplicates the file handle at spawn time; even after
    ``proc.wait()`` returns, the OS can hold the duplicate briefly while
    the kernel reaps the child. A naive ``unlink`` in that window raises
    ``PermissionError: [WinError 32]``. Retry a few times with a short
    backoff, then swallow -- temp files in %TEMP% are not load-bearing
    and the OS will clean them up on reboot.
    """
    for handle_key in ("stdout_f", "stderr_f"):
        try:
            run_state[handle_key].close()
        except Exception:
            pass
    for path_key in ("stdout_path", "stderr_path"):
        p = Path(run_state[path_key])
        for attempt in range(5):
            try:
                p.unlink(missing_ok=True)
                break
            except PermissionError:
                time.sleep(0.1 * (attempt + 1))
            except OSError:
                break


def _drain_stdout_lines(run_state: dict) -> list[dict]:
    """Read new bytes from the stdout temp file since last call, return newly
    completed JSON records, advance the offset stored in run_state.

    The CLI streams one ``{...}`` JSON object per line for multi-target
    runs (single-target also emits one trailing-newline object). We only
    commit complete ``\\n``-terminated lines; a partial line at the tail
    is left for the next tick to merge with subsequent writes.
    """
    path = run_state["stdout_path"]
    offset = run_state.get("stdout_offset", 0)
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            chunk = f.read()
    except OSError:
        return []
    if not chunk:
        return []
    last_nl = chunk.rfind(b"\n")
    if last_nl < 0:
        return []
    complete = chunk[: last_nl + 1]
    run_state["stdout_offset"] = offset + last_nl + 1
    new_records: list[dict] = []
    for line in complete.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list):
            new_records.extend(obj)
        elif isinstance(obj, dict):
            new_records.append(obj)
    return new_records


def _detect_jsonl_encoding(path: Path) -> str:
    """Return a Python codec name matching the file's BOM, if any.

    PowerShell's ``>`` redirect writes UTF-16-LE with a BOM on Windows, so
    a scan_results.jsonl created via a previous ``fp pipeline ... > file``
    invocation is UTF-16 even though Python's default text I/O is UTF-8.
    Mixing UTF-8 appends into a UTF-16 file produces lines that look like
    Chinese glyphs when the consumer reads back as UTF-16 (each pair of
    UTF-8 bytes packs into a U+XXYY code point).

    The codec names below are the *append-safe* variants: ``utf-16-le`` and
    ``utf-16-be`` don't re-emit the BOM, unlike the bare ``utf-16`` codec.
    """
    try:
        if not path.exists() or path.stat().st_size == 0:
            return "utf-8"
        head = path.open("rb").read(4)
    except OSError:
        return "utf-8"
    if head.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if head.startswith(b"\xfe\xff"):
        return "utf-16-be"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def _append_records_to_jsonl(records: list[dict], path: Path) -> int:
    """Append records as JSONL (one object per line) matching the existing
    file's encoding. Returns count appended. Raises OSError on failure --
    caller reports via st.error."""
    if not records:
        return 0
    enc = _detect_jsonl_encoding(path)
    with open(path, "a", encoding=enc) as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return len(records)


_DETECT_LINE_RE = __import__("re").compile(
    r"\[detect\] target=(?P<target>[^|]*?) \| tech=(?P<tech>[^|]*?) \| "
    r"version=(?P<version>[^|]*?) \| url=(?P<url>.*?)\s*$"
)


def _parse_detects_from_stderr(stderr_text: str) -> list[dict]:
    """Pull every `[detect] ...` line emitted by fp.progress.ProgressLogger.detect.

    One row per detected tech across all targets scanned so far in this run.
    Preserves first-seen order; doesn't dedup (a same (tech, version) pair on
    two distinct targets is two rows).
    """
    rows: list[dict] = []
    for line in stderr_text.splitlines():
        m = _DETECT_LINE_RE.search(line)
        if not m:
            continue
        rows.append({
            "target": m.group("target").strip(),
            "tech": m.group("tech").strip(),
            "version": m.group("version").strip(),
            "url": m.group("url").strip(),
        })
    return rows


def _parse_pipeline_stdout(text: str) -> list[dict]:
    """Pipeline emits one JSON record (single target) or a JSON list (multi)."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Some versions emit ndjson; try line-by-line.
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
    if isinstance(data, list):
        return data
    return [data]


def render_scan_tab() -> None:
    st.subheader("Launch a scan")
    st.caption(
        "Runs `python -m fp.cli pipeline <target> --json` from "
        f"`{REPO_ROOT}`. Optional sources (katana, version probes, "
        "cross-page) degrade gracefully if their DBs are missing."
    )

    # --- Targets ---------------------------------------------------------
    targets_raw = st.text_area(
        "Targets (one per line)",
        value="",
        height=120,
        placeholder="https://example.com",
        help="URLs or hostnames. Hostnames get http:// prepended by the scanner. Leave blank if uploading a target file below.",
    )

    files_raw = st.text_input(
        "Or read targets from file(s) (one path per line, comma-separated also ok)",
        value="",
        help=(
            f"Forwarded as --file FILE. Paths relative to {REPO_ROOT}. "
            "Blank lines and # comments inside the file are ignored. "
            f"Example: targets.txt (already exists at {REPO_ROOT / 'targets.txt'})."
        ),
    )

    uploaded_targets = st.file_uploader(
        "...or upload target file(s)",
        type=["txt"],
        accept_multiple_files=True,
        help="Each uploaded file is forwarded as --file FILE. One target per line; blank lines and # comments are ignored.",
    )

    # --- Fetch identity (read-only) --------------------------------------
    with st.expander("Fetch identity (what the scanner actually sends)"):
        st.markdown(
            "- **TLS fingerprint:** `curl_cffi` impersonating `chrome120` "
            "(JA3/JA4 matches real Chrome).\n"
            "- **HTTP headers:** full Chrome 121 shape from "
            "`fetchlib.build_request_headers()` -- `Accept-Language`, "
            "`sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, "
            "`Sec-Fetch-{Dest,Mode,Site,User}`, `Accept-Encoding`, "
            "`Upgrade-Insecure-Requests`.\n"
            "- **User-Agent:** controlled by the UA radio below "
            "(`chrome` preset, `scanner` honest preset, or custom string).\n"
            "- **Fetch strategy:** `curl_cffi` by default, with automatic "
            "Stage 5 escalation to CloakBrowser (stealth Chromium) when "
            "curl_cffi looks blocked. Force the cloak tier from the start "
            "with the checkbox below."
        )

    # --- Basic -----------------------------------------------------------
    col1, col2, col3 = st.columns(3)
    with col1:
        ua_mode = st.radio(
            "User-Agent",
            ["chrome preset", "scanner preset", "custom string"],
            index=0,
            horizontal=False,
        )
        ua_custom = ""
        if ua_mode == "custom string":
            ua_custom = st.text_input(
                "Custom UA", value="MyScanner/1.0",
                help="Verbatim User-Agent header sent for every request",
            )
        depth = st.number_input("Katana depth", 1, 5, 2)
    with col2:
        parallel = st.number_input("Parallel targets", 1, 20, 3)
        concurrency = st.number_input("Per-target scanner concurrency", 1, 100, 20)
        bulk = st.checkbox(
            "Bulk preset",
            value=False,
            help="Halves all stage timeouts and shrinks katana budgets",
        )
        verify_ssl = st.checkbox("Verify SSL", value=False)
    with col3:
        append_to_jsonl = st.checkbox(
            f"Append results to {DEFAULT_JSONL.name}",
            value=True,
            help=f"Path: {DEFAULT_JSONL}",
        )
        use_cloak = st.checkbox(
            "Use CloakBrowser (slow, defeats JS challenges)",
            value=False,
            help=(
                "Replace the scanner's main curl_cffi loop with CloakBrowser "
                "(stealth Chromium). Adds ~1-3s per fetch but cracks "
                "Cloudflare/Akamai JS interstitials curl_cffi can't. "
                "Requires `pip install cloakbrowser`."
            ),
        )
        run_timeout_min = st.number_input(
            "Dashboard hard-timeout (minutes)", 1, 240, 15,
            help="The dashboard kills the subprocess after this many minutes.",
        )

    # --- Sources ---------------------------------------------------------
    st.markdown("**Sources** (all default ON; the CLI silently skips a source whose DB/binary is missing)")
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        katana = st.checkbox("Katana", value=True)
        version_probes = st.checkbox("Version probes", value=True)
    with s2:
        cross_page = st.checkbox("Cross-page rescan", value=True)
        backend_probe = st.checkbox("Backend leak probe", value=True)
    with s3:
        jsextract = st.checkbox("JS path extraction", value=True)
        extract_bodies = st.checkbox("Extract JS bodies", value=True)
    with s4:
        extract_html = st.checkbox("Extract HTML bodies", value=True)

    # --- Advanced --------------------------------------------------------
    with st.expander("DB / cache paths (override defaults)"):
        st.caption(
            f"Paths are resolved relative to `{REPO_ROOT}`. Leave blank to use "
            "the CLI default; missing files are silently skipped."
        )
        db_cache = st.text_input("--cache (nuclei cache.json)", value="cache.json")
        db_db = st.text_input("--db (fingerprints.db)", value="fingerprints.db")
        db_wap = st.text_input("--wap-db (wappalyzer.db)", value="wappalyzer.db")
        db_retire = st.text_input("--retire-db (retirejs.db)", value="retirejs.db")
        db_ww = st.text_input("--ww-db (whatweb.db)", value="whatweb.db")

    with st.expander("Timeouts & budgets (seconds / URL caps)"):
        t1, t2 = st.columns(2)
        with t1:
            req_timeout = st.number_input("--timeout (per-request)", 1, 600, 10)
            scan_timeout = st.number_input("--scan-timeout (nuclei stage)", 5, 3600, 90)
            katana_timeout = st.number_input("--katana-timeout (crawl)", 5, 3600, 60)
        with t2:
            vp_timeout = st.number_input("--vp-timeout (version probes)", 5, 3600, 30)
            cross_page_timeout = st.number_input("--cross-page-timeout", 5, 3600, 120)
            max_katana_urls = st.number_input("--max-katana-urls (URL budget)", 0, 100000, 500)
            max_cross_page_urls = st.number_input("--max-cross-page-urls", 0, 1000, 30)

    run_state = st.session_state.get("_scan_run")
    is_running = run_state is not None and run_state["proc"].poll() is None

    c_start, c_stop = st.columns([1, 1])
    start_clicked = c_start.button("Run scan", type="primary", disabled=is_running)
    stop_clicked = c_stop.button("Stop scan", disabled=not is_running)

    if start_clicked:
        targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
        # Split on newline or comma; tolerate either.
        files: list[str] = []
        for chunk in files_raw.replace(",", "\n").splitlines():
            chunk = chunk.strip()
            if chunk:
                files.append(chunk)

        # Persist uploaded target files to disk so the CLI's --file FILE can read them.
        for idx, up in enumerate(uploaded_targets or []):
            dest = _HERE / f"_uploaded_targets_{idx}.txt"
            dest.write_bytes(up.getvalue())
            files.append(str(dest))

        if not targets and not files:
            st.error("No targets and no --file paths provided.")
            return

        ua_value = ua_custom.strip() if ua_mode == "custom string" else (
            "chrome" if ua_mode.startswith("chrome") else "scanner"
        )
        if ua_mode == "custom string" and not ua_value:
            st.error("Custom UA selected but the string is empty.")
            return

        opts = dict(
            ua=ua_value,
            depth=depth, parallel=parallel, concurrency=concurrency,
            bulk=bulk, verify_ssl=verify_ssl,
            use_cloak=use_cloak,
            katana=katana, version_probes=version_probes,
            cross_page=cross_page, extract_bodies=extract_bodies,
            extract_html=extract_html,
            backend_probe=backend_probe, jsextract=jsextract,
            cache=db_cache.strip(), db=db_db.strip(),
            wap_db=db_wap.strip(), retire_db=db_retire.strip(),
            ww_db=db_ww.strip(),
            timeout=req_timeout, scan_timeout=scan_timeout,
            katana_timeout=katana_timeout, vp_timeout=vp_timeout,
            cross_page_timeout=cross_page_timeout,
            max_katana_urls=max_katana_urls,
            max_cross_page_urls=max_cross_page_urls,
        )
        cmd = _build_pipeline_cmd(targets, files, opts)

        # Stream stdout/stderr to temp files so the OS pipe buffer can't fill
        # and stall the child mid-scan while we wait for it to finish.
        stdout_f = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".out")
        stderr_f = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".err")
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=stdout_f,
            stderr=stderr_f,
        )
        st.session_state["_scan_run"] = {
            "proc": proc,
            "stdout_f": stdout_f, "stderr_f": stderr_f,
            "stdout_path": stdout_f.name, "stderr_path": stderr_f.name,
            "t0": time.monotonic(),
            "cmd": cmd,
            "append": append_to_jsonl,
            "timeout_s": 60 * int(run_timeout_min),
        }
        st.rerun()

    if stop_clicked and run_state is not None:
        proc = run_state["proc"]
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        _cleanup_scan_state(run_state)
        del st.session_state["_scan_run"]
        st.warning("Stopped by user")
        st.rerun()

    if run_state is None:
        return

    proc = run_state["proc"]
    elapsed = time.monotonic() - run_state["t0"]
    st.code(" ".join(shlex.quote(c) for c in run_state["cmd"]), language="bash")

    if proc.poll() is None:
        # Hard-timeout enforcement (the old --timeout knob the synchronous
        # path used; preserved so behaviour matches user expectations).
        if elapsed > run_state["timeout_s"]:
            proc.kill()
            proc.wait()
            _cleanup_scan_state(run_state)
            del st.session_state["_scan_run"]
            st.error(f"Hard timeout after {elapsed:.0f}s")
            return
        st.info(f"Running... {elapsed:.1f}s elapsed (pid={proc.pid}). Press 'Stop scan' to abort.")

        # --- Drain stdout: each newly-completed JSON record is one finished
        # target. Append to scan_results.jsonl line-by-line (NOT bulk on
        # completion) and accumulate for in-UI rendering.
        new_records = _drain_stdout_lines(run_state)
        if new_records:
            if run_state["append"]:
                try:
                    _append_records_to_jsonl(new_records, DEFAULT_JSONL)
                except OSError as e:
                    st.error(f"Could not append to {DEFAULT_JSONL.name}: {e}")
            run_state.setdefault("streamed", []).extend(new_records)

        streamed: list[dict] = run_state.get("streamed", [])

        # Live per-target completion table: each row lists the exact
        # "tech version" pairs detected on that target so the user sees
        # which version belongs to which tech at a glance.
        st.markdown(f"**Targets completed** ({len(streamed)})")
        if streamed:
            comp_rows = []
            for rec in streamed:
                techs = rec.get("techs", []) or []
                pairs = []
                for t in techs:
                    name = t.get("name", "?")
                    ver = t.get("version")
                    pairs.append(f"{name} {ver}" if ver else f"{name} (no version)")
                comp_rows.append({
                    "target": rec.get("target", "?"),
                    "tech versions": ", ".join(pairs) if pairs else "(none)",
                })
            st.dataframe(
                pd.DataFrame(comp_rows, columns=["target", "tech versions"]),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("(no target finished yet)")

        # Live per-detection table: tech and version combined into one
        # explicit value-pair column so it's unambiguous which version
        # belongs to which tech.
        try:
            raw = Path(run_state["stderr_path"]).read_bytes()
            tail = raw.decode("utf-8", errors="replace")
        except OSError:
            tail = ""
        rows = _parse_detects_from_stderr(tail)
        st.markdown(f"**Detections so far** ({len(rows)})")
        if rows:
            display_rows = []
            for r in rows:
                ver = r["version"]
                tech_version = (
                    f"{r['tech']} {ver}" if ver and ver != "-"
                    else f"{r['tech']} (no version)"
                )
                display_rows.append({
                    "target": r["target"],
                    "tech version": tech_version,
                    "url": r["url"] if r["url"] and r["url"] != "-" else "",
                })
            st.dataframe(
                pd.DataFrame(display_rows, columns=["target", "tech version", "url"]),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("(no tech detected yet)")

        time.sleep(1.0)
        st.rerun()
        return

    # --- Process finished ---
    rc = proc.returncode
    # Close the writer handles BEFORE reading; on Windows, opening the same
    # path for read while the writer handle is still open can also hit
    # PermissionError on some FS configurations.
    for handle_key in ("stdout_f", "stderr_f"):
        try:
            run_state[handle_key].close()
        except Exception:
            pass
    # Final tail drain: stream any bytes the polling loop missed between the
    # last 1-second tick and process exit (including the final record).
    final_records = _drain_stdout_lines(run_state)
    if final_records:
        if run_state["append"]:
            try:
                _append_records_to_jsonl(final_records, DEFAULT_JSONL)
            except OSError as e:
                st.error(f"Could not append final batch to {DEFAULT_JSONL.name}: {e}")
        run_state.setdefault("streamed", []).extend(final_records)

    records: list[dict] = list(run_state.get("streamed", []))
    stderr = Path(run_state["stderr_path"]).read_text(encoding="utf-8", errors="replace")
    _cleanup_scan_state(run_state)
    del st.session_state["_scan_run"]

    if rc != 0:
        st.error(f"Failed (exit {rc}) after {elapsed:.1f}s")
        with st.expander("stderr", expanded=True):
            st.code(stderr or "(empty)")
        # Note: any records that were already streamed remain appended -- the
        # JSONL file is left consistent with the partial work that completed.
        if records:
            st.info(f"{len(records)} record(s) were streamed and appended to {DEFAULT_JSONL.name} before failure.")
        return

    st.success(f"Done in {elapsed:.1f}s - {len(records)} record(s) (streamed line-by-line)")

    if stderr:
        with st.expander("stderr"):
            st.code(stderr)

    if not records:
        st.warning("Pipeline returned no JSON records.")
        return

    # Quick summary
    for rec in records:
        target = rec.get("target", "?")
        techs = rec.get("techs", []) or []
        with st.expander(f"{target} - {len(techs)} tech(s)", expanded=len(records) == 1):
            if techs:
                rows = [
                    {
                        "name": t.get("name"),
                        "version": t.get("version") or "",
                        "confidence": t.get("version_confidence") or "",
                        "sources": ",".join(t.get("sources", []) or []),
                        "evidence_urls": len(t.get("evidence", []) or []),
                    }
                    for t in techs
                ]
                st.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.json(rec, expanded=False)


# ---------------------------------------------------------------------------
# Analyze tab
# ---------------------------------------------------------------------------

def _load_analysis(path: Path) -> analyzer.AnalysisResult | None:
    if not path.exists():
        st.warning(f"File not found: {path}")
        return None
    try:
        return analyzer.analyze_file(path)
    except Exception as e:
        st.error(f"Failed to read {path}: {e}")
        return None


def render_analyze_tab() -> None:
    st.subheader("Analyze scan_results.jsonl")

    col1, col2 = st.columns([3, 1])
    with col1:
        path_str = st.text_input(
            "JSONL path",
            value=str(DEFAULT_JSONL),
            help="Absolute or working-dir-relative path to a scan_results.jsonl",
        )
    with col2:
        st.write("")
        st.write("")
        refresh = st.button("Reload")

    uploaded = st.file_uploader(
        "...or upload a JSONL file",
        type=["jsonl", "json", "txt"],
        accept_multiple_files=False,
    )

    if uploaded is not None:
        # Persist to a temp file so analyzer.open_safe can detect encoding.
        tmp = Path(st.session_state.get("_tmp_uploaded_path", _HERE / "_uploaded.jsonl"))
        tmp.write_bytes(uploaded.getvalue())
        st.session_state["_tmp_uploaded_path"] = str(tmp)
        path = tmp
    else:
        path = Path(path_str)

    if refresh:
        st.cache_data.clear()  # no-op if we didn't cache; future-proofing

    result = _load_analysis(path)
    if result is None:
        return

    # Stash result for the Report tab.
    st.session_state["_analysis"] = result
    st.session_state["_analysis_path"] = str(path)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Targets", result.total_targets)
    m2.metric("Detections", result.total_techs)
    m3.metric("Unique techs", result.unique_techs)
    m4.metric("Bad lines", result.bad_lines)

    st.divider()

    # --- Top techs ---
    st.markdown("### Top techs")
    c1, c2 = st.columns(2)
    with c1:
        st.caption("Most detected overall")
        df = pd.DataFrame(result.top_techs(15), columns=["tech", "count"])
        st.bar_chart(df, x="tech", y="count", height=320)
    with c2:
        st.caption("Most detected with a version string")
        df = pd.DataFrame(result.top_techs_with_version(15), columns=["tech", "count"])
        st.bar_chart(df, x="tech", y="count", height=320)

    # --- Version coverage ---
    st.markdown("### Version coverage")
    cov_df = pd.DataFrame(result.coverage_rows())
    st.dataframe(cov_df, use_container_width=True, height=360)

    # --- Tech + version pairs ---
    st.markdown("### Top (tech, version) pairs")
    pairs = [
        {"tech": t, "version": v, "count": c}
        for (t, v), c in result.top_tech_version_pairs(20)
    ]
    st.dataframe(pd.DataFrame(pairs), use_container_width=True)

    # --- Multi-version techs ---
    st.markdown("### Techs detected at multiple versions")
    mv = result.techs_with_multiple_versions()
    if mv:
        st.dataframe(
            pd.DataFrame(
                [{"tech": t, "versions": ", ".join(vs), "n_versions": len(vs)} for t, vs in mv]
            ),
            use_container_width=True,
        )
    else:
        st.caption("(none)")

    # --- Never-versioned techs ---
    st.markdown("### Techs never seen with a version")
    nv = result.techs_never_versioned()
    if nv:
        st.dataframe(
            pd.DataFrame(nv, columns=["tech", "targets"]),
            use_container_width=True,
        )
    else:
        st.caption("(none)")

    # --- URL leaks ---
    st.markdown("### Top URLs leaking version")
    leaks = result.top_url_leaks(50)
    if leaks:
        st.dataframe(
            pd.DataFrame(leaks, columns=["url", "hits"]),
            use_container_width=True,
            height=360,
        )
    else:
        st.caption("(none)")

    # --- Tech -> URL sample ---
    with st.expander("Tech -> sample URLs"):
        for tech, urls in result.tech_url_samples(sample=5):
            st.markdown(f"**{tech}**")
            for u in urls:
                st.code(u)


# ---------------------------------------------------------------------------
# Report tab
# ---------------------------------------------------------------------------

def _result_to_markdown(result: analyzer.AnalysisResult, src: str) -> str:
    buf = io.StringIO()
    buf.write(f"# Fingerprinter report\n\n")
    buf.write(f"Source: `{src}`\n\n")
    buf.write(f"- Targets: **{result.total_targets}**\n")
    buf.write(f"- Detections: **{result.total_techs}**\n")
    buf.write(f"- Unique techs: **{result.unique_techs}**\n")
    buf.write(f"- Bad lines: {result.bad_lines}\n\n")

    buf.write("## Top techs\n\n")
    for tech, count in result.top_techs(20):
        buf.write(f"- {tech}: {count}\n")

    buf.write("\n## Version coverage\n\n")
    buf.write("| tech | total | with | without | coverage |\n")
    buf.write("|---|---:|---:|---:|---:|\n")
    for row in result.coverage_rows():
        buf.write(
            f"| {row['tech']} | {row['total']} | {row['with_version']} | "
            f"{row['without_version']} | {row['coverage_pct']}% |\n"
        )

    buf.write("\n## Top (tech, version) pairs\n\n")
    for (t, v), c in result.top_tech_version_pairs(20):
        buf.write(f"- {t} {v}: {c}\n")

    buf.write("\n## Techs with multiple versions\n\n")
    for tech, vs in result.techs_with_multiple_versions():
        buf.write(f"- {tech}: {', '.join(vs)}\n")

    buf.write("\n## Top version-leaking URLs (50)\n\n")
    for url, hits in result.top_url_leaks(50):
        buf.write(f"- `{url}` -> {hits}\n")

    return buf.getvalue()


def render_report_tab() -> None:
    st.subheader("Export report")

    result: analyzer.AnalysisResult | None = st.session_state.get("_analysis")
    src = st.session_state.get("_analysis_path", "")

    if result is None:
        st.info("Open the Analyze tab first and load a JSONL file.")
        return

    st.caption(f"Source: `{src}`")
    st.write(
        f"**{result.total_targets}** targets - "
        f"**{result.total_techs}** detections - "
        f"**{result.unique_techs}** unique techs"
    )

    md = _result_to_markdown(result, src)
    st.download_button(
        "Download Markdown report",
        md.encode("utf-8"),
        file_name="fingerprinter_report.md",
        mime="text/markdown",
    )

    cov_csv = pd.DataFrame(result.coverage_rows()).to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download coverage.csv",
        cov_csv,
        file_name="coverage.csv",
        mime="text/csv",
    )

    pairs_csv = pd.DataFrame(
        [{"tech": t, "version": v, "count": c}
         for (t, v), c in result.top_tech_version_pairs(1000)]
    ).to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download tech_versions.csv",
        pairs_csv,
        file_name="tech_versions.csv",
        mime="text/csv",
    )

    leaks_csv = pd.DataFrame(result.top_url_leaks(1000), columns=["url", "hits"])\
        .to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download url_leaks.csv",
        leaks_csv,
        file_name="url_leaks.csv",
        mime="text/csv",
    )

    with st.expander("Preview markdown"):
        st.markdown(md)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="Fingerprinter Dashboard",
        layout="wide",
    )
    st.title("Fingerprinter Dashboard")
    st.caption(f"Working dir: `{REPO_ROOT}`")

    tab_scan, tab_analyze, tab_report = st.tabs(["Scan", "Analyze", "Report"])
    with tab_scan:
        render_scan_tab()
    with tab_analyze:
        render_analyze_tab()
    with tab_report:
        render_report_tab()


if __name__ == "__main__":
    main()
