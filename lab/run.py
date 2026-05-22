"""Fingerprint-rule lab orchestrator.

Reads manifest.yaml, boots each container, waits for readiness, runs the
fingerprint scanner against it, records results, tears down. Produces a
coverage report: tech detected? version correct? false positives?

Usage:
    python lab/run.py                      # run all fixtures
    python lab/run.py --only nginx-1-25-3  # single fixture
    python lab/run.py --keep               # don't stop containers after scan
    python lab/run.py --json results.json  # also write full detection dump
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LAB_DIR = Path(__file__).parent
REPO_ROOT = LAB_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "fingerprinter"))

from fp import cache as cache_mod  # noqa: E402
from fp import scanner as scanner_mod  # noqa: E402
from fp import wappalyzer as wap_mod  # noqa: E402

import record as record_mod  # noqa: E402
import diff as diff_mod  # noqa: E402

CONTAINER_PREFIX = "fp-lab-"
DEFAULT_READY_TIMEOUT = 60
DEFAULT_READY_STATUSES = [200, 301, 302, 401, 403, 404]


# ---------------------------------------------------------------------------
# Docker lifecycle
# ---------------------------------------------------------------------------


@dataclass
class ReadyProbe:
    path: str = "/"
    statuses: list[int] = field(default_factory=lambda: list(DEFAULT_READY_STATUSES))
    timeout: int = DEFAULT_READY_TIMEOUT


@dataclass
class Fixture:
    id: str
    port: int
    expected_tech: str
    expected_version: str
    image: str | None = None
    compose: str | None = None
    container_port: int = 80
    ready: ReadyProbe = field(default_factory=ReadyProbe)
    setup: str | None = None
    setup_ready: ReadyProbe | None = None

    @property
    def container(self) -> str:
        return f"{CONTAINER_PREFIX}{self.id}"

    @property
    def url(self) -> str:
        return f"http://localhost:{self.port}"

    @property
    def is_compose(self) -> bool:
        return bool(self.compose)


def _probe(d: dict | None, default_timeout: int = DEFAULT_READY_TIMEOUT) -> ReadyProbe:
    d = d or {}
    return ReadyProbe(
        path=d.get("path", "/"),
        statuses=d.get("status", list(DEFAULT_READY_STATUSES)),
        timeout=d.get("timeout", default_timeout),
    )


def load_fixtures(manifest_path: Path, only: list[str] | None) -> list[Fixture]:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    fixtures: list[Fixture] = []
    for f in data["fixtures"]:
        fx = Fixture(
            id=f["id"],
            port=f["port"],
            expected_tech=f["expected"]["tech"],
            expected_version=f["expected"]["version"],
            image=f.get("image"),
            compose=f.get("compose"),
            container_port=f.get("container_port", 80),
            ready=_probe(f.get("ready")),
            setup=f.get("setup"),
            setup_ready=_probe(f["setup_ready"], 60) if f.get("setup_ready") else None,
        )
        if only and fx.id not in only:
            continue
        fixtures.append(fx)
    return fixtures


def docker(*args: str, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, env=env
    )


def _compose_cmd(fx: Fixture) -> list[str]:
    compose_path = LAB_DIR / fx.compose
    return ["compose", "-f", str(compose_path), "-p", fx.container]


def _compose_env(fx: Fixture) -> dict:
    import os
    env = dict(os.environ)
    env["HOST_PORT"] = str(fx.port)
    return env


def ensure_stopped(fx: Fixture) -> None:
    if fx.is_compose:
        docker(*_compose_cmd(fx), "down", "-v", check=False, env=_compose_env(fx))
    else:
        docker("rm", "-f", fx.container, check=False)


def start(fx: Fixture) -> None:
    if fx.is_compose:
        docker(*_compose_cmd(fx), "up", "-d", env=_compose_env(fx))
    else:
        docker(
            "run", "-d", "--rm",
            "--name", fx.container,
            "-p", f"{fx.port}:{fx.container_port}",
            fx.image,
        )


def wait_ready(fx: Fixture, probe: ReadyProbe) -> bool:
    deadline = time.time() + probe.timeout
    url = fx.url + probe.path
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "fp-lab/1"})
            with urllib.request.urlopen(req, timeout=3) as r:
                if r.status in probe.statuses:
                    return True
        except urllib.error.HTTPError as e:
            if e.code in probe.statuses:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def run_setup(fx: Fixture) -> tuple[bool, str]:
    if not fx.setup:
        return True, ""
    script = LAB_DIR / fx.setup
    if not script.exists():
        return False, f"setup script not found: {script}"
    proc = subprocess.run(
        [sys.executable, str(script), fx.url],
        capture_output=True, text=True,
    )
    msg = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, msg


# ---------------------------------------------------------------------------
# Scan + assess
# ---------------------------------------------------------------------------


@dataclass
class FixtureResult:
    fixture: Fixture
    booted: bool
    ready: bool
    detections: list[dict] = field(default_factory=list)
    error: str | None = None

    def assess(self) -> dict:
        expected_t = self.fixture.expected_tech.lower()
        expected_v = self.fixture.expected_version
        tech_hit = False
        version_exact = False
        version_partial = False
        matched_versions: list[str] = []

        for d in self.detections:
            name = (d.get("name") or "").lower()
            if expected_t in name:
                tech_hit = True
                version = d.get("version") or _first_extracted_version(d)
                if version:
                    matched_versions.append(version)
                    if version == expected_v:
                        version_exact = True
                    elif expected_v.startswith(version) or version.startswith(expected_v.split(".")[0]):
                        version_partial = True

        return {
            "tech_hit": tech_hit,
            "version_exact": version_exact,
            "version_partial": version_partial,
            "matched_versions": matched_versions,
            "total_detections": len(self.detections),
            "error": self.error,
        }


def _first_extracted_version(d: dict) -> str | None:
    ex = d.get("extracted") or {}
    for k in ("version", "Version"):
        if ex.get(k):
            return ex[k][0]
    for values in ex.values():
        if values:
            return values[0]
    return None


async def scan_fixtures(
    fixtures: list[Fixture],
    *,
    cache_path: Path | None,
    db_path: Path | None,
    wap_db_path: Path | None,
    keep: bool,
    record_dir: Path | None = None,
) -> list[FixtureResult]:
    cache = cache_mod.load_cache(cache_path) if cache_path else cache_mod.build_cache(db_path)
    wap_cache = wap_mod.build_cache(wap_db_path) if wap_db_path else None

    results: list[FixtureResult] = []
    for fx in fixtures:
        label = fx.compose if fx.is_compose else fx.image
        print(f"\n-> {fx.id} ({label}) on :{fx.port}")
        res = FixtureResult(fixture=fx, booted=False, ready=False)
        try:
            ensure_stopped(fx)
            start(fx)
            res.booted = True
            print(f"  waiting for readiness ({fx.ready.path}) ...", end="", flush=True)
            if not wait_ready(fx, fx.ready):
                print(" timeout")
                res.error = "readiness timeout"
                results.append(res)
                continue
            print(" ready")
            res.ready = True
            if fx.setup:
                print("  running setup ...", end="", flush=True)
                ok, msg = run_setup(fx)
                if not ok:
                    print(f" FAILED: {msg}")
                    res.error = f"setup failed: {msg}"
                    results.append(res)
                    continue
                print(f" ok ({msg})" if msg else " ok")
                if fx.setup_ready:
                    print(f"  post-setup readiness ({fx.setup_ready.path}) ...", end="", flush=True)
                    if not wait_ready(fx, fx.setup_ready):
                        print(" timeout")
                        res.error = "post-setup readiness timeout"
                        results.append(res)
                        continue
                    print(" ready")
            if record_dir is not None:
                print("  recording probe responses ...", end="", flush=True)
                probes = await record_mod.record_target(
                    fx.url, record_mod.DEFAULT_PROBE_PATHS, timeout=5.0, concurrency=10
                )
                record_mod.write_recording(
                    record_dir, fx.id, fx.url,
                    fx.expected_tech, fx.expected_version, probes,
                )
                ok = sum(1 for r in probes if "error" not in r)
                print(f" {ok}/{len(probes)}")
            scan = await scanner_mod.scan_targets(
                cache, [fx.url], wap_cache=wap_cache, timeout=5, concurrency=20
            )
            res.detections = scan.get(fx.url, [])
            print(f"  {len(res.detections)} detection(s)")
        except subprocess.CalledProcessError as exc:
            res.error = (exc.stderr or exc.stdout or str(exc)).strip().splitlines()[-1]
            print(f"  docker error: {res.error}")
        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"
            print(f"  error: {res.error}")
        finally:
            if not keep:
                ensure_stopped(fx)
        results.append(res)
    return results


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def render_report(results: list[FixtureResult]) -> None:
    print("\n" + "=" * 72)
    print(f"{'FIXTURE':<20} {'EXPECTED':<28} {'TECH':<6} {'VER':<6} NOTES")
    print("-" * 72)
    tech_hits = 0
    version_exact = 0
    for r in results:
        a = r.assess()
        expected = f"{r.fixture.expected_tech} {r.fixture.expected_version}"
        tech = "YES" if a["tech_hit"] else "no"
        if a["version_exact"]:
            ver = "EXACT"
            version_exact += 1
        elif a["version_partial"]:
            ver = "part"
        elif a["matched_versions"]:
            ver = "wrong"
        else:
            ver = "-"
        notes = a["error"] or ""
        if a["matched_versions"]:
            notes = ("got=" + ",".join(a["matched_versions"][:3])) + (" " + notes).rstrip()
        if a["tech_hit"]:
            tech_hits += 1
        print(f"{r.fixture.id:<20} {expected:<28} {tech:<6} {ver:<6} {notes}")
    n = len(results)
    print("-" * 72)
    print(
        f"Tech coverage: {tech_hits}/{n} ({_pct(tech_hits, n)})  "
        f"Version exact: {version_exact}/{n} ({_pct(version_exact, n)})"
    )


def _pct(num: int, denom: int) -> str:
    return f"{(num / denom * 100):.0f}%" if denom else "-"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(LAB_DIR / "manifest.yaml"))
    ap.add_argument("--only", nargs="+", help="Run only these fixture ids")
    ap.add_argument("--cache", default=str(REPO_ROOT / "fingerprinter" / "cache.json"))
    ap.add_argument("--db", default=str(REPO_ROOT / "fingerprinter" / "fingerprints.db"))
    ap.add_argument("--wap-db", default=str(REPO_ROOT / "fingerprinter" / "wappalyzer.db"))
    ap.add_argument("--keep", action="store_true", help="Keep containers running after scan")
    ap.add_argument("--json", help="Write full result dump to this path")
    ap.add_argument("--record", metavar="DIR",
                    help="Record probe responses per fixture into DIR/<fixture_id>/responses.json")
    ap.add_argument("--diff", metavar="DIR",
                    help="Record into DIR and then mine candidate extractors via lab/diff.py")
    args = ap.parse_args()

    # check docker
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("ERROR: `docker` CLI not available or daemon not running", file=sys.stderr)
        return 2

    fixtures = load_fixtures(Path(args.manifest), args.only)
    if not fixtures:
        print("No fixtures selected", file=sys.stderr)
        return 2

    cache_path = Path(args.cache) if Path(args.cache).exists() else None
    db_path = Path(args.db) if cache_path is None and Path(args.db).exists() else None
    if cache_path is None and db_path is None:
        print("ERROR: neither cache.json nor fingerprints.db found; run `fp parse/build-cache` first", file=sys.stderr)
        return 2
    wap_db_path = Path(args.wap_db) if Path(args.wap_db).exists() else None
    if wap_db_path is None:
        print("(note: no Wappalyzer DB found; scanning with nuclei rules only)", file=sys.stderr)

    record_dir: Path | None = None
    if args.diff:
        record_dir = Path(args.diff)
    elif args.record:
        record_dir = Path(args.record)
    if record_dir is not None:
        record_dir.mkdir(parents=True, exist_ok=True)

    results = asyncio.run(
        scan_fixtures(
            fixtures,
            cache_path=cache_path,
            db_path=db_path,
            wap_db_path=wap_db_path,
            keep=args.keep,
            record_dir=record_dir,
        )
    )
    render_report(results)

    if args.diff:
        print("\nRunning diff miner ...")
        by_tech = diff_mod.run_diff(record_dir)
        diff_mod.write_reports(record_dir, by_tech)
        total = sum(len(v) for v in by_tech.values())
        print(f"Diff: {len(by_tech)} tech group(s) with pairs, {total} candidate(s)")
        for tech, cands in by_tech.items():
            hdr = sum(1 for c in cands if c.source == "header")
            body = sum(1 for c in cands if c.source == "body")
            high = sum(1 for c in cands if c.confidence == "high")
            print(f"  {tech}: {len(cands)} ({hdr}h/{body}b, {high} high-confidence)")
        print(f"Reports: {record_dir / 'candidates'}/")

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                [
                    {
                        "id": r.fixture.id,
                        "image": r.fixture.image,
                        "expected": {
                            "tech": r.fixture.expected_tech,
                            "version": r.fixture.expected_version,
                        },
                        "assessment": r.assess(),
                        "detections": r.detections,
                    }
                    for r in results
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nWrote {args.json}")

    # Non-zero exit if any fixture failed to boot.
    return 0 if all(r.booted and r.ready for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
