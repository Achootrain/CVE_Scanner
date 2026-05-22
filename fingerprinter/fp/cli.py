"""Command-line entry point: `python -m fp.cli {parse|build-cache|scan|wap-import|wap-cache|subdomains} ...`."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from textwrap import shorten

from . import cache as cache_mod
from . import collector as collector_mod
from . import detect_version as dv_mod
from . import interactive as interactive_mod
from . import katana as katana_mod
from . import parser as parser_mod
from . import pipeline as pipeline_mod
from . import retirejs as retire_mod
from . import scanner as scanner_mod
from . import whatweb as ww_mod
from . import subdomains as sub_mod
from . import wappalyzer as wap_mod


# ---------------------------------------------------------------------------
# Nuclei pipeline
# ---------------------------------------------------------------------------


def _cmd_parse(args: argparse.Namespace) -> int:
    schema = Path(args.schema) if args.schema else Path(__file__).with_name("schema.sql")
    summary = parser_mod.load_directory(Path(args.templates), Path(args.db), schema)
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_build_cache(args: argparse.Namespace) -> int:
    cache = cache_mod.build_cache(args.db)
    if args.out:
        cache_mod.dump_cache(cache, args.out)
    print(json.dumps(cache["stats"], indent=2))
    return 0


# ---------------------------------------------------------------------------
# Wappalyzer pipeline
# ---------------------------------------------------------------------------


def _cmd_wap_import(args: argparse.Namespace) -> int:
    if args.zip:
        blob = Path(args.zip).read_bytes()
    else:
        print(f"Downloading {wap_mod.WAP_ZIP_URL} ...", file=sys.stderr)
        blob = asyncio.run(wap_mod.fetch_zip())
    data = wap_mod.parse_zip(blob)
    stats = wap_mod.import_to_db(data, args.db)
    print(json.dumps(stats, indent=2))
    return 0


def _cmd_wap_cache(args: argparse.Namespace) -> int:
    cache = wap_mod.build_cache(args.db)
    print(json.dumps(cache["stats"], indent=2))
    return 0


# ---------------------------------------------------------------------------
# Retire.js pipeline
# ---------------------------------------------------------------------------


def _cmd_retire_import(args: argparse.Namespace) -> int:
    if args.json:
        blob = Path(args.json).read_bytes()
    else:
        print(f"Downloading {retire_mod.RETIREJS_URL} ...", file=sys.stderr)
        blob = asyncio.run(retire_mod.fetch_repo())
    data = retire_mod.parse_repo(blob)
    stats = retire_mod.import_to_db(data, args.db)
    print(json.dumps(stats, indent=2))
    return 0


def _cmd_retire_cache(args: argparse.Namespace) -> int:
    cache = retire_mod.build_cache(args.db)
    print(json.dumps(cache["stats"], indent=2))
    return 0


# ---------------------------------------------------------------------------
# Lab rules pipeline
# ---------------------------------------------------------------------------


def _cmd_lab_import(args: argparse.Namespace) -> int:
    from . import lab_rules as lab_mod
    stats = lab_mod.build_db(args.lab_dir, args.db)
    print(json.dumps(stats, indent=2))
    return 0


def _cmd_lab_cache(args: argparse.Namespace) -> int:
    from . import lab_rules as lab_mod
    cache = lab_mod.build_cache(args.db)
    summary = {
        "libs": len(cache.libs_by_slug),
        "body_rules": sum(len(v) for v in cache.body_rules_by_slug.values()),
        "bundled_rules": sum(len(v) for v in cache.bundled_rules_by_parent.values()),
        "url_rules": len(cache.url_rules),
    }
    print(json.dumps(summary, indent=2))
    return 0


# ---------------------------------------------------------------------------
# WhatWeb pipeline
# ---------------------------------------------------------------------------


def _cmd_ww_import(args: argparse.Namespace) -> int:
    stats = asyncio.run(ww_mod.import_whatweb(args.db, zip_path=args.zip or None))
    print(json.dumps(stats, indent=2))
    return 0


def _cmd_ww_cache(args: argparse.Namespace) -> int:
    patterns = ww_mod.build_cache(args.db)
    techs = len({p.tech_name for p in patterns})
    print(json.dumps({"patterns": len(patterns), "technologies": techs}, indent=2))
    return 0





# ---------------------------------------------------------------------------
# JS extract
# ---------------------------------------------------------------------------





# ---------------------------------------------------------------------------
# Katana (Phase 7) -- static endpoint extraction via the katana binary
# ---------------------------------------------------------------------------


def _cmd_katana(args: argparse.Namespace) -> int:
    """Phase 7: shell out to katana, dedup output, optionally extract paths."""
    if not katana_mod.find_katana_binary():
        sys.stderr.write(katana_mod.INSTALL_HINT)
        return 2

    try:
        result = asyncio.run(
            katana_mod.crawl(
                args.url,
                depth=args.depth,
                headless=args.headless,
                jsluice=args.jsluice,
                katana_concurrency=args.katana_concurrency,
                max_katana_urls=args.max_katana_urls,
                max_js_files=args.max_js,
                max_html_files=args.max_html,
                max_templates_per_host=args.max_templates_per_host,
                katana_timeout=args.timeout,
                extract_bodies=args.extract_bodies,
                extract_html=args.extract_html,
            )
        )
    except RuntimeError as exc:
        sys.stderr.write(str(exc))
        return 2
    except asyncio.TimeoutError:
        sys.stderr.write(
            f"katana timed out after {args.timeout}s.\n"
            f"This usually means a high-cardinality site (forum, e-commerce)\n"
            f"is being crawled exhaustively at depth {args.depth}.\n"
            f"Try one of:\n"
            f"  --depth 1                       (limit hops; biggest impact)\n"
            f"  --katana-concurrency 3          (fewer parallel fetches, less RAM)\n"
            f"  --timeout 600                   (give it more wall-clock)\n"
            f"Or run without --extract-bodies first to see how many JS URLs\n"
            f"are surfaced before paying the per-body fetch cost.\n"
        )
        return 3

    # Surface budget exhaustion as a stderr warning so users notice their
    # output is bounded, not a complete crawl. The signal is also exposed
    # via stats.katana_budget_hit for programmatic callers.
    if result.stats.get("katana_budget_hit"):
        budget = result.stats.get("katana_url_budget", "?")
        sys.stderr.write(
            f"warning: URL budget ({budget}) reached -- katana terminated early.\n"
            f"Output reflects the first {budget} unique URLs only. To see more:\n"
            f"  --max-katana-urls 1000          (raise the cap)\n"
            f"  --max-templates-per-host 2      (squeeze fan-out further)\n"
            f"  --depth 1                       (avoid second-hop fan-out)\n"
        )

    if args.json:
        out = {
            "seed": result.seed,
            "page_urls": result.page_urls,
            "js_urls": result.js_urls,
            "paths": [ep.to_dict() for ep in result.paths],
            "config_leaks": [cl.to_dict() for cl in result.config_leaks],
            "stats": result.stats,
        }
        print(json.dumps(out, indent=2))
        return 0

    print(f"=== katana {result.seed} ===")
    print(json.dumps(result.stats, indent=2))
    print()
    if result.js_urls:
        print(f"-- {len(result.js_urls)} unique JS file(s) --")
        for u in result.js_urls:
            print(f"  {u}")
    if result.paths:
        print()
        order = {"call": 0, "api": 1, "template": 2}
        print(f"-- {len(result.paths)} extracted path(s) --")
        for ep in sorted(result.paths, key=lambda x: (order.get(x.confidence, 9), x.path)):
            print(f"  [{ep.confidence:8}] {ep.path}")
    if result.config_leaks:
        print()
        print(f"-- {len(result.config_leaks)} config blob leak(s) --")
        # Order: backend_url > api_key > auth_id > feature_flag (most actionable first)
        klass_order = {"backend_url": 0, "api_key": 1, "auth_id": 2, "feature_flag": 3}
        for cl in sorted(
            result.config_leaks,
            key=lambda x: (klass_order.get(x.leak_class, 9), x.framework, x.key_path),
        ):
            print(f"  [{cl.leak_class:13}] {cl.framework:11} {cl.key_path} = {cl.value}")
    if args.list_pages:
        print()
        print(f"-- {len(result.page_urls)} deduped page URL(s) --")
        for u in result.page_urls:
            print(f"  {u}")
    return 0


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------


def _cmd_subdomains(args: argparse.Namespace) -> int:
    results = asyncio.run(sub_mod.enumerate_all(args.domains))
    if args.json:
        print(json.dumps(results, indent=2))
        return 0
    for d, subs in results.items():
        print(f"\n=== {d} ({len(subs)}) ===")
        for s in subs:
            print(f"  {s}")
    return 0


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def _cmd_scan(args: argparse.Namespace) -> int:
    cache = cache_mod.load_cache(args.cache) if args.cache else cache_mod.build_cache(args.db)
    wap_cache = None
    if args.wap_db:
        wap_cache = wap_mod.build_cache(args.wap_db)
    retire_cache = None
    if args.retire_db:
        retire_cache = retire_mod.build_cache(args.retire_db)

    targets = list(args.targets)
    if args.expand_subdomains:
        enum = asyncio.run(sub_mod.enumerate_all(args.targets))
        expanded: list[str] = []
        for apex, subs in enum.items():
            expanded.extend(subs or [apex])
        # Dedupe while preserving order.
        seen: set[str] = set()
        targets = [t for t in expanded if not (t in seen or seen.add(t))]
        print(f"Expanded to {len(targets)} subdomains", file=sys.stderr)

    results = asyncio.run(
        scanner_mod.scan_targets(
            cache,
            targets,
            wap_cache=wap_cache,
            retire_cache=retire_cache,
            backend_probe=args.backend_probe,
            jsextract=args.jsextract,
            concurrency=args.concurrency,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
        )
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        _render_human(results)
    return 0


def _render_human(results: dict) -> None:
    for target, detections in results.items():
        print(f"\n=== {target} ===")
        if not detections:
            print("  (no detections)")
            continue
        seen: set[tuple] = set()
        for d in detections:
            key = (d["source"], d["template_id"], d.get("matcher_name"), d["path"])
            if key in seen:
                continue
            seen.add(key)
            label = d["name"]
            if d.get("matcher_name"):
                label += f" :: {d['matcher_name']}"
            extras = []
            version = d.get("version") or _first_extracted_version(d)
            if version:
                extras.append(f"v{version}")
            if d.get("vendor") and d.get("product"):
                extras.append(f"{d['vendor']}/{d['product']}")
            if d.get("confidence") is not None and d["source"] == "wappalyzer":
                extras.append(f"{d['confidence']}%")
            tail = f"  [{'; '.join(extras)}]" if extras else ""
            src = d["source"][:3]
            print(f"  [{src}] {d['template_id']:<35} {label}{tail}")


def _first_extracted_version(d: dict) -> str | None:
    ex = d.get("extracted") or {}
    for k in ("version", "Version"):
        v = ex.get(k)
        if v:
            return v[0]
    for values in ex.values():
        if values:
            return values[0]
    return None


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------


def _cmd_pipeline(args: argparse.Namespace) -> int:
    """End-to-end fully-automated tech+version fingerprint scan.

    No browser, no session -- pure unauthenticated probing. Composes
    scanner (nuclei + Wappalyzer + retire.js + backend-leak probes +
    jsextract), katana (static endpoint + config-blob leak extraction),
    and the hand-curated version-probe catalog.
    """
    # Merge --file targets with positional targets.
    targets: list[str] = list(args.targets)
    for path in args.file:
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
            targets += [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        except OSError as e:
            print(f"error: cannot read --file {path}: {e}", file=sys.stderr)
            return 1
    if not targets:
        print("error: no targets provided (pass URLs or use --file)", file=sys.stderr)
        return 1
    args.targets = targets

    # Apply --bulk preset before anything else. Individual flags still
    # win because argparse defaults are set at parse time; we only
    # override when the user did NOT explicitly pass the timeout flag
    # (i.e., the value still equals the argparse default).
    if getattr(args, "bulk", False):
        _BULK = {
            "scan_timeout": (90, 45),
            "katana_timeout": (60, 30),
            "max_katana_urls": (500, 100),
            "max_cross_page_urls": (30, 10),
            "cross_page_timeout": (120, 60),
        }
        for attr, (default, bulk_val) in _BULK.items():
            if getattr(args, attr) == default:
                setattr(args, attr, bulk_val)

    # Drop default paths that don't exist on disk; the pipeline degrades
    # gracefully when an optional source is absent, so users without
    # cache.json / wappalyzer.db / retirejs.db get a sensible run instead
    # of FileNotFoundError.
    def _exists_or_none(p: str | None) -> str | None:
        return p if p and Path(p).exists() else None

    cache = _exists_or_none(args.cache)
    db = None if cache else _exists_or_none(args.db)
    cfg = pipeline_mod.PipelineConfig(
        nuclei_cache=cache,
        fingerprints_db=db,
        wap_db=_exists_or_none(args.wap_db),
        retire_db=_exists_or_none(args.retire_db),
        ww_db=_exists_or_none(args.ww_db),
        lab_db=_exists_or_none(args.lab_db),
        backend_probe=args.backend_probe,
        jsextract=args.jsextract,
        run_katana=args.katana,
        katana_extract_html=args.extract_html,
        katana_extract_bodies=args.extract_bodies,
        katana_max_urls=args.max_katana_urls,
        katana_depth=args.depth,
        run_version_probes=args.version_probes,
        run_cross_page_rescan=args.cross_page,
        cross_page_max_urls=args.max_cross_page_urls,
        concurrency=args.concurrency,
        timeout=args.timeout,
        scan_timeout=args.scan_timeout,
        katana_timeout=args.katana_timeout,
        vp_timeout=args.vp_timeout,
        cross_page_timeout=args.cross_page_timeout,
        verify_ssl=args.verify_ssl,
        user_agent=args.ua,
        quiet=args.quiet,
        save_responses=args.save_responses,
        use_cloak=args.use_cloak,
    )
    if len(args.targets) == 1:
        result = asyncio.run(pipeline_mod.run_pipeline(args.targets[0], cfg))
        if args.json:
            print(json.dumps(result, default=str))
        else:
            _render_pipeline(result, show_evidence=args.show_evidence)
        return 0

    # Multi-target: stream results and flush after each so partial runs are
    # not lost on interrupt. JSON output is one record per line (JSONL).
    async def _stream() -> None:
        async for result in pipeline_mod.run_pipeline_stream(
            args.targets, cfg, parallel=args.parallel
        ):
            if args.json:
                print(json.dumps(result, default=str), flush=True)
            else:
                _render_pipeline(result, show_evidence=args.show_evidence)

    asyncio.run(_stream())
    return 0


def _render_pipeline(payload, *, show_evidence: bool = True) -> None:
    """Compact text rendering of pipeline output.

    ``show_evidence`` adds 1-3 sample evidence URLs under each tech so the
    user can see which routes confirmed each detection without reaching
    for ``--json``. Default ON; pass ``--no-evidence`` to suppress for
    bandwidth-constrained terminals.
    """
    items = payload if isinstance(payload, list) else [payload]
    for entry in items:
        target = entry["target"]
        stats = entry.get("stats", {})
        print(f"\n=== {target} ===")

        # UA being used (truncated; full string in --json)
        ua = stats.get("user_agent", "")
        if ua:
            short_ua = ua if len(ua) <= 60 else ua[:57] + "..."
            print(f"  user-agent: {short_ua}")

        skipped = stats.get("skipped") or []
        if skipped:
            print(f"  skipped: {', '.join(skipped)}")
        errors = stats.get("errors") or []
        if errors:
            print(f"  errors: {', '.join(errors)}")

        print(
            f"  detections={stats.get('scan_detections', 0)} "
            f"cross_page={stats.get('cross_page_detections', 0)} "
            f"probe_hits={stats.get('version_probe_hits', 0)} "
            f"techs={stats.get('techs_total', 0)} "
            f"with_version={stats.get('techs_with_version', 0)}"
        )

        # Cross-page rescan visibility (only when it actually ran).
        cp = stats.get("cross_page") or {}
        if cp:
            print(
                f"  cross-page rescan: fetched={cp.get('urls_fetched', 0)}"
                f"/{cp.get('urls_after_dedup', 0)} html={cp.get('urls_html', 0)} "
                f"wap_hits={cp.get('wap_detections', 0)} "
                f"retire_hits={cp.get('retire_detections', 0)}"
            )

        # Katana visibility: was it run, what did it find?
        kstats = stats.get("katana") or {}
        leaks = entry.get("leaks") or {}
        endpoints = entry.get("endpoints") or []
        if kstats or endpoints or leaks.get("config_blob"):
            kr = kstats.get("katana_records", 0)
            pgs = kstats.get("page_urls_deduped", 0)
            jsu = kstats.get("js_urls_deduped", 0)
            cfg_n = kstats.get("config_leaks_total", len(leaks.get("config_blob") or []))
            budget_hit = kstats.get("katana_budget_hit", False)
            tag = " [BUDGET HIT]" if budget_hit else ""
            # Break down endpoints by discovery source so users see what
            # contributed.
            buckets: dict[str, int] = {}
            for e in endpoints:
                key = e.get("discovered_by", "?")
                buckets[key] = buckets.get(key, 0) + 1
            print(
                f"  katana: records={kr} pages={pgs} js={jsu} "
                f"config_leaks={cfg_n}{tag}"
            )
            if endpoints:
                breakdown = ", ".join(
                    f"{k}={v}" for k, v in sorted(buckets.items())
                )
                print(f"  endpoints: total={len(endpoints)} ({breakdown})")
        elif "katana" not in str(skipped):
            # Katana ran but truly returned nothing -- still useful to say so
            # explicitly so the user can distinguish from "skipped".
            print("  katana: (no records)")

        techs = entry.get("techs") or []
        if not techs:
            print("  (no techs detected)")
        else:
            for t in techs:
                ver = f"v{t['version']}" if t["version"] else "(no version)"
                src = ",".join(t.get("sources") or [])
                print(f"  {t['name']:<28} {ver:<14} [{src}]")
                if show_evidence:
                    # Pull distinct evidence URLs in insertion order so
                    # the seed-scan URL stays first; show up to three.
                    seen: set = set()
                    urls: list[str] = []
                    for ev in t.get("evidence") or []:
                        u = ev.get("url") or ""
                        if not u or u in seen:
                            continue
                        seen.add(u)
                        urls.append(u)
                        if len(urls) >= 3:
                            break
                    total = len({(ev.get("url") or "") for ev in t.get("evidence") or [] if ev.get("url")})
                    for u in urls:
                        # Trim long URLs so terminal wrap doesn't make
                        # the listing unreadable on narrow windows.
                        short = u if len(u) <= 72 else u[:69] + "..."
                        print(f"      evidence: {short}")
                    if total > len(urls):
                        print(f"      evidence: ... and {total - len(urls)} more URL(s)")

        hosts = leaks.get("backend_hosts") or []
        if hosts:
            print(f"  backend hosts leaked: {', '.join(hosts[:8])}"
                  f"{' ...' if len(hosts) > 8 else ''}")

        # Sample a few config-blob leaks so the user sees what's in there
        # without dumping the full list (they can use --json for that).
        cfg_leaks = leaks.get("config_blob") or []
        if cfg_leaks:
            sample = cfg_leaks[:5]
            print(f"  config_leaks ({len(cfg_leaks)} total, showing {len(sample)}):")
            for cl in sample:
                v = cl.get("value", "")
                if len(v) > 60:
                    v = v[:57] + "..."
                print(f"    [{cl.get('leak_class','?'):<13}] {cl.get('framework','?'):<11} "
                      f"{cl.get('key_path','?')} = {v}")

        unfinished = entry.get("unfinished") or []
        if unfinished:
            print(f"  unfinished (not run): {', '.join(unfinished)}")


def _cmd_collect(args: argparse.Namespace) -> int:
    """Crawl URLs with Crawl4AI and write JSONL for detect-version."""
    targets: list[str] = list(args.targets)
    for path in args.file:
        try:
            targets += collector_mod.load_targets(path)
        except OSError as exc:
            sys.stderr.write(f"error: cannot read --file {path}: {exc}\n")
            return 1
    if not targets:
        sys.stderr.write("error: no targets provided (pass URLs or use --file)\n")
        return 1

    try:
        records = asyncio.run(
            collector_mod.collect(
                targets,
                follow_js=args.follow_js,
                concurrency=args.concurrency,
                user_agent=args.ua or None,
            )
        )
    except RuntimeError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    if not records:
        sys.stderr.write("warning: no records collected\n")
        return 0

    out_path = Path(args.out) if args.out else None
    html_count = sum(1 for r in records if r.record_type == "html")
    js_count = sum(1 for r in records if r.record_type == "js")
    sys.stderr.write(
        f"[collect] total: {len(records)} records "
        f"(html={html_count} js={js_count})\n"
    )

    def _write(line: str) -> None:
        if out_path:
            with open(out_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        else:
            print(line)

    for rec in records:
        _write(json.dumps(rec.to_dict(), default=str))

    if out_path:
        sys.stderr.write(f"Output written to {out_path}\n")
    return 0


def _cmd_detect_version(args: argparse.Namespace) -> int:
    """AI-powered tech-version detection from pre-crawled JSONL data."""
    input_path = Path(args.input)
    if not input_path.exists():
        sys.stderr.write(f"error: {input_path} does not exist\n")
        return 1

    try:
        results = dv_mod.run_detect_version(
            input_path,
            provider=args.provider or None,
            model=args.model or None,
            api_key=args.api_key or None,
            base_url=args.base_url or None,
        )
    except RuntimeError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    out_path = Path(args.out) if args.out else None

    def _emit(obj: dict) -> None:
        line = json.dumps(obj, default=str)
        if out_path:
            with open(out_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        else:
            print(line)

    if args.json:
        for entry in results:
            _emit(entry)
    else:
        for entry in results:
            target = entry["target"]
            stats = entry.get("stats", {})
            techs = entry.get("techs") or []
            print(f"\n=== {target} ===")
            print(
                f"  records={stats.get('records_read', 0)} "
                f"model={stats.get('model', '?')} "
                f"techs={stats.get('techs_total', 0)} "
                f"with_version={stats.get('techs_with_version', 0)}"
            )
            if not techs:
                print("  (no techs detected)")
            else:
                for t in techs:
                    ver = f"v{t['version']}" if t["version"] else "(no version)"
                    conf = t.get("version_confidence") or ""
                    conf_tag = f" [{conf}]" if conf and t["version"] else ""
                    ev = (t.get("evidence") or [{}])[0].get("quote") or ""
                    ev_short = shorten(ev, 60, placeholder="...") if ev else ""
                    print(f"  {t['name']:<30} {ver:<16}{conf_tag}")
                    if ev_short:
                        print(f"    evidence: {ev_short}")
        if out_path:
            sys.stderr.write(f"Results appended to {out_path}\n")
    return 0


def _cmd_interactive(args: argparse.Namespace) -> int:
    return interactive_mod.run_shell()


def _cmd_setup_cloak(args: argparse.Namespace) -> int:
    """Pre-download CloakBrowser's stealth Chromium binary (~200 MB) with
    live progress.

    Without this, the first scan that touches the cloak tier (--use-cloak
    or Stage 5 auto-escalation) silently spends several minutes inside
    ssl.read() pulling the binary. Running this once moves that cost out
    of the scan path and caches the binary to ``~/.cloakbrowser``.
    """
    import os
    import pathlib
    import threading
    import time
    try:
        from cloakbrowser import ensure_binary, binary_info
        from cloakbrowser.config import get_cache_dir
    except ImportError:
        print(
            "cloakbrowser not installed -- pip install cloakbrowser",
            file=sys.stderr,
        )
        return 1

    # Fast path: already installed.
    try:
        info = binary_info()
        if info and info.get("installed"):
            print(
                f"[cloak] binary already present at {info.get('binary_path')}",
                file=sys.stderr,
            )
            return 0
    except Exception:  # noqa: BLE001
        pass

    cache_dir = pathlib.Path(get_cache_dir())
    print(
        f"[cloak] downloading stealth Chromium (~200 MB, first run only)\n"
        f"[cloak] cache: {cache_dir}",
        file=sys.stderr, flush=True,
    )

    # Run ensure_binary() in a worker thread; poll cache_dir size from the
    # main thread to surface bytes-on-disk as real progress. Pure stat
    # calls -- no hooking into cloakbrowser's internal httpx stream
    # required, so this stays robust across cloakbrowser version bumps.
    err: list[BaseException] = []
    result: list = []

    def _worker() -> None:
        try:
            result.append(ensure_binary())
        except BaseException as exc:  # noqa: BLE001
            err.append(exc)

    th = threading.Thread(target=_worker, daemon=True)
    t0 = time.monotonic()
    th.start()

    def _dir_size(p: pathlib.Path) -> int:
        total = 0
        try:
            for f in p.rglob("*"):
                if f.is_file():
                    try:
                        total += f.stat().st_size
                    except OSError:
                        pass
        except OSError:
            pass
        return total

    last_bytes = -1
    while th.is_alive():
        bytes_now = _dir_size(cache_dir)
        elapsed = time.monotonic() - t0
        rate = bytes_now / elapsed if elapsed > 0 else 0
        # Carriage-return progress line so it refreshes in place.
        sys.stderr.write(
            f"\r[cloak] {bytes_now / 1024 / 1024:7.1f} MB on disk "
            f"({elapsed:6.1f}s, {rate / 1024 / 1024:5.2f} MB/s)   "
        )
        sys.stderr.flush()
        last_bytes = bytes_now
        time.sleep(0.5)
    th.join()
    sys.stderr.write("\n")
    sys.stderr.flush()

    if err:
        print(f"[cloak] download failed: {err[0]}", file=sys.stderr)
        return 1
    final_path = result[0] if result else "<unknown>"
    print(
        f"[cloak] done in {time.monotonic() - t0:.1f}s -> {final_path}",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    # curl_cffi prefers add_reader (Selector loop); Windows ProactorEventLoop
    # lacks it and curl_cffi falls back to a selector-thread bridge (slower,
    # prints CurlCffiWarning). Default to Selector to avoid both costs.
    #
    # Exception: CloakBrowser's async driver needs `loop.subprocess_exec`
    # to spawn its node child, which Selector raises NotImplementedError
    # on. When the user opted into the cloak tier we keep the OS default
    # Proactor and let curl_cffi take its bridge path -- still correct,
    # just noisier.
    import sys as _sys, asyncio as _asyncio
    if _sys.platform == "win32":
        _argv = argv if argv is not None else _sys.argv
        if "--use-cloak" not in _argv:
            _asyncio.set_event_loop_policy(_asyncio.WindowsSelectorEventLoopPolicy())

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="fp")
    # No subcommand -> drop into the interactive shell. This is friendlier
    # than printing the usage wall on first run.
    sub = ap.add_subparsers(dest="cmd", required=False)

    p_parse = sub.add_parser("parse", help="Parse YAML templates into SQLite")
    p_parse.add_argument("templates", help="Path to http/technologies directory")
    p_parse.add_argument("db", help="Path to SQLite DB (will be created)")
    p_parse.add_argument("--schema", help="Override schema.sql path")
    p_parse.set_defaults(func=_cmd_parse)

    p_cache = sub.add_parser("build-cache", help="Build in-memory cache, optionally dump to JSON")
    p_cache.add_argument("db")
    p_cache.add_argument("--out", help="Write cache JSON to this path")
    p_cache.set_defaults(func=_cmd_build_cache)

    p_wimport = sub.add_parser(
        "wap-import",
        help="Fetch Wappalyzer rules from enthec/webappanalyzer and import to SQLite",
    )
    p_wimport.add_argument("--db", default="wappalyzer.db")
    p_wimport.add_argument("--zip", help="Import from a local zip file instead of downloading")
    p_wimport.set_defaults(func=_cmd_wap_import)

    p_wcache = sub.add_parser("wap-cache", help="Build in-memory Wappalyzer cache from DB")
    p_wcache.add_argument("--db", default="wappalyzer.db")
    p_wcache.set_defaults(func=_cmd_wap_cache)

    p_rimport = sub.add_parser(
        "retire-import",
        help="Fetch retire.js jsrepository.json and import to SQLite",
    )
    p_rimport.add_argument("--db", default="retirejs.db")
    p_rimport.add_argument("--json", help="Import from a local jsrepository.json instead of downloading")
    p_rimport.set_defaults(func=_cmd_retire_import)

    p_rcache = sub.add_parser("retire-cache", help="Build in-memory retire.js cache from DB")
    p_rcache.add_argument("--db", default="retirejs.db")
    p_rcache.set_defaults(func=_cmd_retire_cache)

    p_limport = sub.add_parser(
        "lab-import",
        help="Walk lab/research/ and import every version_rules.json + rules.json into lab.db",
    )
    p_limport.add_argument("--lab-dir", default="../lab/research",
                           help="Root of the lab dir to walk (default: ../lab/research)")
    p_limport.add_argument("--db", default="lab.db")
    p_limport.set_defaults(func=_cmd_lab_import)

    p_lcache = sub.add_parser("lab-cache", help="Inspect lab.db: per-kind rule counts")
    p_lcache.add_argument("--db", default="lab.db")
    p_lcache.set_defaults(func=_cmd_lab_cache)

    p_wwimport = sub.add_parser(
        "whatweb-import",
        help="Fetch WhatWeb plugins from GitHub and import version patterns to SQLite",
    )
    p_wwimport.add_argument("--db", default="whatweb.db")
    p_wwimport.add_argument("--zip", help="Import from a local WhatWeb master.zip instead of downloading")
    p_wwimport.set_defaults(func=_cmd_ww_import)

    p_wwcache = sub.add_parser("whatweb-cache", help="Show WhatWeb DB stats")
    p_wwcache.add_argument("--db", default="whatweb.db")
    p_wwcache.set_defaults(func=_cmd_ww_cache)



    p_subs = sub.add_parser("subdomains", help="Enumerate subdomains via crt.sh")
    p_subs.add_argument("domains", nargs="+", help="Apex domains")
    p_subs.add_argument("--json", action="store_true")
    p_subs.set_defaults(func=_cmd_subdomains)

    p_scan = sub.add_parser("scan", help="Scan one or more targets")
    p_scan.add_argument("targets", nargs="+", help="Target URLs or hostnames")
    p_scan.add_argument("--db", default="fingerprints.db")
    p_scan.add_argument("--cache", help="Load JSON cache instead of rebuilding from DB")
    p_scan.add_argument("--wap-db", help="Wappalyzer SQLite DB (enables version detection)")
    p_scan.add_argument("--retire-db", help="Retire.js SQLite DB (enables JS-library version detection)")
    p_scan.add_argument(
        "--backend-probe",
        action="store_true",
        help="Sweep fetched script bodies for backend-host references (Supabase, Firebase, Hasura, ...) "
             "and send reflective probes to each candidate host to confirm provider via response shape",
    )
    p_scan.add_argument(
        "--jsextract",
        action="store_true",
        help=(
            "Extract API paths from fetched JS bundles and probe each one. "
            "Paths are ranked call > api > template by extraction confidence "
            "and capped at " + str(scanner_mod.MAX_JSEXTRACT_PATHS) + " probes per target. "
            "Requires scripts to be present (works alongside --retire-db or standalone)."
        ),
    )
    p_scan.add_argument(
        "--expand-subdomains",
        action="store_true",
        help="Expand each target into its subdomains via crt.sh before scanning",
    )
    p_scan.add_argument("--concurrency", type=int, default=scanner_mod.DEFAULT_CONCURRENCY)
    p_scan.add_argument("--timeout", type=int, default=scanner_mod.DEFAULT_TIMEOUT)
    p_scan.add_argument("--verify-ssl", action="store_true")
    p_scan.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    p_scan.set_defaults(func=_cmd_scan)



    p_katana = sub.add_parser(
        "katana",
        help="Phase 7: static endpoint extraction via the katana binary "
             "(no auth needed). Applies template + canonical-URL + body-SHA1 "
             "dedup so high-cardinality sites do not bloat the JS-fetch budget.",
    )
    p_katana.add_argument("url", help="Seed URL")
    p_katana.add_argument(
        "--depth",
        type=int,
        default=katana_mod.DEFAULT_DEPTH,
        help=f"Katana crawl depth (default: {katana_mod.DEFAULT_DEPTH}). "
             "This is the primary bandwidth control on forum-style sites.",
    )
    p_katana.add_argument(
        "--headless",
        action="store_true",
        help="Pass -headless to katana (Chromium hybrid crawl, slower but "
             "executes JS for SPA-bundled targets)",
    )
    p_katana.add_argument(
        "--jsluice",
        action="store_true",
        help="Pass -jsl to katana (jsluice JS parsing). "
             "Memory intensive; use only when default extraction misses endpoints.",
    )
    p_katana.add_argument(
        "--max-js",
        type=int,
        default=katana_mod.DEFAULT_MAX_JS_FILES,
        help=f"Cap unique JS files retained after dedup "
             f"(default: {katana_mod.DEFAULT_MAX_JS_FILES})",
    )
    p_katana.add_argument(
        "--max-templates-per-host",
        type=int,
        default=katana_mod.DEFAULT_MAX_TEMPLATES_PER_HOST,
        help=f"Cap visits per (host, path-template) so /threads/"
             f"{{n}} does not dominate output "
             f"(default: {katana_mod.DEFAULT_MAX_TEMPLATES_PER_HOST})",
    )
    p_katana.add_argument(
        "--timeout",
        type=int,
        default=katana_mod.DEFAULT_KATANA_TIMEOUT,
        help=f"Katana subprocess wall-clock timeout in seconds "
             f"(default: {katana_mod.DEFAULT_KATANA_TIMEOUT}). "
             f"Forum-style sites with --depth 2+ may need 600+.",
    )
    p_katana.add_argument(
        "--katana-concurrency",
        type=int,
        default=katana_mod.DEFAULT_KATANA_CONCURRENCY,
        help=f"Katana internal parallel-fetch concurrency "
             f"(default: {katana_mod.DEFAULT_KATANA_CONCURRENCY}; "
             f"upstream default is 10). Lower to cap RAM in containers, "
             f"raise for faster crawls on small sites.",
    )
    p_katana.add_argument(
        "--max-katana-urls",
        type=int,
        default=katana_mod.DEFAULT_MAX_KATANA_URLS,
        help=f"URL-budget cap: terminate katana once N unique URLs have "
             f"been observed (default: {katana_mod.DEFAULT_MAX_KATANA_URLS}). "
             f"This is the safety net that lets --depth 2 stay safe on "
             f"forum-style sites with thousands of thread URLs. Pass 0 to "
             f"disable and let katana run to completion.",
    )
    p_katana.add_argument(
        "--extract-bodies",
        action="store_true",
        help="Re-fetch each unique JS body and run regex extraction "
             "(call/api/template tiers). Adds Layer 3 SHA1 body dedup. "
             "Without this flag the command only emits the deduped URL list.",
    )
    p_katana.add_argument(
        "--extract-html",
        action="store_true",
        help="Also re-fetch each unique deduped page URL and sweep the HTML "
             "for form actions, data-href attrs, htmx directives, and inline "
             "<script> blocks. Use this on hybrid / server-rendered targets "
             "(XenForo, ASP.NET, traditional PHP, server-rendered Rails) "
             "where the API surface lives in HTML, not JS bundles. "
             "Independent of --extract-bodies; pass both for the union.",
    )
    p_katana.add_argument(
        "--max-html",
        type=int,
        default=katana_mod.DEFAULT_MAX_HTML_FILES,
        help=f"Cap unique HTML pages re-fetched under --extract-html "
             f"(default: {katana_mod.DEFAULT_MAX_HTML_FILES})",
    )
    p_katana.add_argument(
        "--list-pages",
        action="store_true",
        help="In text mode, also print the deduped page URL list",
    )
    p_katana.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON",
    )
    p_katana.set_defaults(func=_cmd_katana)

    p_pipeline = sub.add_parser(
        "pipeline",
        help="End-to-end automated tech+version fingerprint scan "
             "(scan + katana + version probes; no browser/session). "
             "Designed for mass-scan AI-training ground-truth collection.",
    )
    p_pipeline.add_argument("targets", nargs="*", help="Target URLs or hostnames")
    p_pipeline.add_argument(
        "--file", "-f", metavar="FILE", action="append", default=[],
        help="Read targets from FILE (one per line; blank lines and # comments ignored). "
             "Can be repeated. Combined with any positional targets.",
    )
    p_pipeline.add_argument("--db", default="fingerprints.db",
                             help="Nuclei fingerprints DB (used if --cache absent)")
    p_pipeline.add_argument("--cache", default="cache.json",
                             help="Pre-built nuclei cache JSON (default: ./cache.json)")
    p_pipeline.add_argument("--wap-db", default="wappalyzer.db",
                             help="Wappalyzer SQLite DB (default: ./wappalyzer.db)")
    p_pipeline.add_argument("--retire-db", default="retirejs.db",
                             help="Retire.js SQLite DB (default: ./retirejs.db)")
    p_pipeline.add_argument("--lab-db", default="lab.db",
                            help="Path to lab.db (built via `fp lab-import`). "
                                 "If absent, the lab-rules source is silently skipped.")
    p_pipeline.add_argument("--ww-db", default="whatweb.db",
                             help="WhatWeb SQLite DB (default: ./whatweb.db)")
    p_pipeline.add_argument(
        "--no-backend-probe", dest="backend_probe",
        action="store_false", default=True,
        help="Disable cross-host backend-leak probes",
    )
    p_pipeline.add_argument(
        "--no-jsextract", dest="jsextract",
        action="store_false", default=True,
        help="Disable JS path extraction probes",
    )
    p_pipeline.add_argument(
        "--no-katana", dest="katana",
        action="store_false", default=True,
        help="Skip katana even if the binary is installed",
    )
    p_pipeline.add_argument(
        "--no-extract-html", dest="extract_html",
        action="store_false", default=True,
        help="Disable katana HTML body sweep (drops config-blob leak extraction)",
    )
    p_pipeline.add_argument(
        "--no-extract-bodies", dest="extract_bodies",
        action="store_false", default=True,
        help="Disable katana JS body re-fetch + regex extraction. "
             "Default ON: every unique deduped JS bundle is fetched and "
             "swept for endpoint paths and config-blob leaks. Pass this "
             "to skip the per-body fetch cost on bandwidth-constrained runs.",
    )
    p_pipeline.add_argument(
        "--no-version-probes", dest="version_probes",
        action="store_false", default=True,
        help="Disable hand-curated version-probe catalog",
    )
    p_pipeline.add_argument(
        "--no-cross-page", dest="cross_page",
        action="store_false", default=True,
        help="Disable cross-page rescan: by default, after katana finishes, "
             "the pipeline re-fetches up to --max-cross-page-urls of the "
             "discovered page URLs and runs Wappalyzer + retire.js against "
             "each. Picks up tech that only fires on non-root routes "
             "(admin, login, API 404s) without paying the nuclei path-probe "
             "fanout cost.",
    )
    p_pipeline.add_argument(
        "--max-cross-page-urls", type=int, default=30,
        help="Cap on katana page URLs re-fetched in the cross-page rescan "
             "(default: 30, matches the HTML-sweep budget)",
    )
    p_pipeline.add_argument("--depth", type=int, default=2,
                             help="Katana crawl depth (default: 2)")
    p_pipeline.add_argument("--max-katana-urls", type=int, default=500,
                             help="Katana URL-budget cap (default: 500)")
    p_pipeline.add_argument("--concurrency", type=int, default=20,
                             help="Per-target scanner concurrency (default: 20)")
    p_pipeline.add_argument("--timeout", type=int, default=10,
                             help="Per-request timeout seconds (default: 10)")
    p_pipeline.add_argument("--scan-timeout", type=int, default=90,
                             help="Hard cap on the nuclei scan stage in seconds (default: 90)")
    p_pipeline.add_argument("--katana-timeout", type=int, default=60,
                             help="Hard cap on the katana crawl stage in seconds (default: 60)")
    p_pipeline.add_argument("--vp-timeout", type=int, default=30,
                             help="Hard cap on the version-probe catalog in seconds (default: 30)")
    p_pipeline.add_argument("--cross-page-timeout", type=int, default=120,
                             help="Hard cap on the cross-page rescan in seconds (default: 120)")
    p_pipeline.add_argument("--parallel", type=int, default=3,
                             help="Targets processed in parallel (default: 3)")
    p_pipeline.add_argument(
        "--bulk", action="store_true",
        help="Bulk-scan preset: halves all stage timeouts and shrinks katana "
             "budgets so a large target list moves faster. Equivalent to "
             "--scan-timeout 45 --katana-timeout 30 --max-katana-urls 100 "
             "--max-cross-page-urls 10 --cross-page-timeout 60. Individual "
             "timeout flags still override this preset when both are given.",
    )
    p_pipeline.add_argument("--verify-ssl", action="store_true")
    p_pipeline.add_argument(
        "--use-cloak", action="store_true",
        help="Run the scanner's main fetch loop through CloakBrowser "
             "(stealth Chromium) instead of curl_cffi. Defeats JS-challenge "
             "interstitials (Cloudflare, Akamai) curl_cffi cannot crack but "
             "pays roughly 1-3s per fetch. Requires `pip install cloakbrowser` "
             "(the stealth binary auto-downloads on first run). "
             "Script-body fetch + backend probes still use curl_cffi. "
             "If omitted, Stage 5 of the funnel will still auto-escalate to "
             "CloakBrowser when curl_cffi appears blocked.",
    )
    p_pipeline.add_argument(
        "--ua",
        default="chrome",
        metavar="PRESET_OR_STRING",
        help="User-Agent: preset 'scanner' (honest scanner UA) or 'chrome' "
             "(Chrome 121 desktop -- bypasses Cloudflare/Akamai bot management; "
             "default for mass-scan use), OR a verbatim UA string. "
             "Cloudflare-fronted forums/news/e-commerce targets typically need "
             "'chrome' for Wappalyzer's HTML-shape rules to fire.",
    )
    p_pipeline.add_argument("--json", action="store_true",
                             help="Emit JSON (one record or list per multi-target run)")
    p_pipeline.add_argument(
        "--quiet", action="store_true",
        help="Suppress live progress logs on stderr. Default: print "
             "timestamped per-stage events ([12.3s] scan: done ...) plus a "
             "10-second heartbeat naming any still-running stages so you can "
             "tell a slow stage from a hung run. Stdout (text or --json) is "
             "unaffected.",
    )
    p_pipeline.add_argument(
        "--no-evidence", dest="show_evidence",
        action="store_false", default=True,
        help="In text output, suppress the 'evidence: <url>' lines under "
             "each detected tech. Default ON shows up to 3 distinct URLs "
             "per tech so you can see which routes confirmed each detection "
             "without reaching for --json.",
    )
    p_pipeline.add_argument(
        "--save-responses", default=None, metavar="DIR",
        help="Archive HTTP responses + tech labels as JSONL to DIR for AI "
             "training data collection. Creates two files per target: "
             "<host>.responses.jsonl (base64 body + headers) and "
             "<host>.labels.jsonl (tech/version labels). Joined by body SHA1.",
    )
    p_pipeline.set_defaults(func=_cmd_pipeline)

    p_collect = sub.add_parser(
        "collect",
        help="Crawl URLs with Crawl4AI and write JSONL for `fp detect-version`. "
             "Requires: pip install crawl4ai && crawl4ai-setup",
    )
    p_collect.add_argument(
        "targets", nargs="*",
        help="Target URLs to crawl.",
    )
    p_collect.add_argument(
        "--file", "-f", metavar="FILE", action="append", default=[],
        help="Read targets from FILE (one URL per line, # lines ignored). Repeatable.",
    )
    p_collect.add_argument(
        "--out", default=None, metavar="FILE",
        help="Write JSONL output to FILE instead of stdout.",
    )
    p_collect.add_argument(
        "--no-js", dest="follow_js", action="store_false", default=True,
        help="Skip fetching linked JavaScript files (only record HTML pages).",
    )
    p_collect.add_argument(
        "--concurrency", type=int, default=3,
        help="Number of URLs to crawl in parallel (default: 3).",
    )
    p_collect.add_argument(
        "--ua", default=None, metavar="USER_AGENT",
        help="Override the default browser User-Agent string.",
    )
    p_collect.set_defaults(func=_cmd_collect)

    p_dv = sub.add_parser(
        "detect-version",
        help="AI-powered tech-version detection from pre-crawled JSONL data. "
             "Feeds Crawl4AI output to a Claude agent which identifies "
             "technologies and versions from HTML, headers, and JS content. "
             "Requires ANTHROPIC_API_KEY.",
    )
    p_dv.add_argument(
        "input",
        metavar="FILE",
        help="JSONL file to process (Crawl4AI output or any JSONL with at "
             "least a 'url' field). Optional fields: html/body, "
             "headers/response_headers, status_code.",
    )
    p_dv.add_argument(
        "--provider",
        default=None,
        choices=("openai", "copilot", "anthropic"),
        help="AI provider to use (default: auto-detected from env vars). "
             "'openai' / 'copilot': uses OPENAI_API_KEY or GITHUB_TOKEN + "
             "optional OPENAI_BASE_URL. 'anthropic': uses ANTHROPIC_API_KEY.",
    )
    p_dv.add_argument(
        "--model",
        default=None,
        metavar="MODEL_ID",
        help="Model to use (default: gpt-4o-mini for openai, "
             "claude-haiku-4-5-20251001 for anthropic, "
             "or DETECT_VERSION_MODEL env var).",
    )
    p_dv.add_argument(
        "--base-url",
        default=None,
        metavar="URL",
        help="OpenAI-compatible API base URL. "
             "GitHub Models: https://models.inference.ai.azure.com -- "
             "set this + GITHUB_TOKEN to use Copilot without a paid OpenAI key.",
    )
    p_dv.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="API key override (default: OPENAI_API_KEY / GITHUB_TOKEN / ANTHROPIC_API_KEY).",
    )
    p_dv.add_argument(
        "--json",
        action="store_true",
        help="Emit JSONL output (one record per target, same schema as "
             "scan_results.jsonl produced by `fp pipeline`)",
    )
    p_dv.add_argument(
        "--out",
        default=None,
        metavar="FILE",
        help="Append JSONL output to this file instead of stdout.",
    )
    p_dv.set_defaults(func=_cmd_detect_version)

    p_interactive = sub.add_parser(
        "interactive",
        help="Menu-driven shell -- pick a workflow, fill in args via prompts",
    )
    p_interactive.set_defaults(func=_cmd_interactive)

    p_setup_cloak = sub.add_parser(
        "setup-cloak",
        help="Pre-download CloakBrowser's stealth Chromium binary (~200 MB). "
             "Run once before any --use-cloak / Stage 5 escalation scan so "
             "the first-run download doesn't blow past the scan timeout.",
    )
    p_setup_cloak.set_defaults(func=_cmd_setup_cloak)

    args = ap.parse_args(argv)
    if not getattr(args, "cmd", None):
        return _cmd_interactive(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
