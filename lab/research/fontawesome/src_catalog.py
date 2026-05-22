"""Inventory version-bearing artifacts across FA release source trees.

Reads:
    lab/research/fontawesome/out/source/FA-<ver>/Font-Awesome-<ver>/...
    lab/research/fontawesome/out/source/FortAwesome_Font-Awesome-7.2.0/Font-Awesome-7.2.0/...

Writes:
    lab/research/fontawesome/src_artifact_inventory.json
    lab/research/fontawesome/src_artifact_inventory.md

Purpose: per release, record (a) banner string in CSS files, (b) canonical CSS
filenames present, (c) webfont filenames present, (d) css class-prefix patterns
observed, (e) package.json version. This is the SOURCE OF TRUTH that rules.json
must cite back to.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from collections import Counter


HERE = Path(__file__).resolve().parent
SOURCE_DIR = HERE / "out" / "source"
OUT_JSON = HERE / "src_artifact_inventory.json"
OUT_MD = HERE / "src_artifact_inventory.md"


# Release dir layout: parent dir contains a single Font-Awesome-<v> sub-dir
RELEASES = {
    "4.7.0":  SOURCE_DIR / "FA-4.7.0"  / "Font-Awesome-4.7.0",
    "5.15.4": SOURCE_DIR / "FA-5.15.4" / "Font-Awesome-5.15.4",
    "6.5.2":  SOURCE_DIR / "FA-6.5.2"  / "Font-Awesome-6.5.2",
    "7.2.0":  SOURCE_DIR / "FortAwesome_Font-Awesome-7.2.0" / "Font-Awesome-7.2.0",
}


BANNER_RX = re.compile(r"/\*!?(?:\s|\*)*(Font\s*Awesome[^*]+?)\*/", re.S | re.I)
PKG_VERSION_RX = re.compile(r'"version"\s*:\s*"([^"]+)"')
CSS_CLASS_RX = re.compile(r"\.([a-z][a-z0-9-]*)\s*[,{]")


def find_css_dir(release_dir: Path) -> Path | None:
    """v4: css/, v5+: css/ at root. v4 has fonts/, v5+ has webfonts/."""
    for p in (release_dir / "css", release_dir / "scss"):
        if p.is_dir():
            return p
    return None


def find_font_dir(release_dir: Path) -> Path | None:
    for p in (release_dir / "webfonts", release_dir / "fonts"):
        if p.is_dir():
            return p
    return None


def read_banner(css_file: Path) -> str | None:
    try:
        head = css_file.read_text(encoding="utf-8", errors="replace")[:1200]
    except Exception:
        return None
    m = BANNER_RX.search(head)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return None


def pkg_version(release_dir: Path) -> str | None:
    pkg = release_dir / "package.json"
    if not pkg.exists():
        return None
    try:
        m = PKG_VERSION_RX.search(pkg.read_text(encoding="utf-8", errors="replace"))
        return m.group(1) if m else None
    except Exception:
        return None


def catalog_release(version: str, release_dir: Path) -> dict:
    """Inventory one release."""
    info: dict = {"version": version, "exists": release_dir.is_dir(), "path": str(release_dir)}
    if not release_dir.is_dir():
        return info

    css_dir = find_css_dir(release_dir)
    font_dir = find_font_dir(release_dir)
    info["css_dir"] = str(css_dir.relative_to(release_dir)) if css_dir else None
    info["font_dir"] = str(font_dir.relative_to(release_dir)) if font_dir else None

    # CSS filenames
    css_files = sorted([p.name for p in css_dir.glob("*.css")]) if css_dir else []
    info["css_files"] = css_files

    # Webfont filenames (woff2 primarily; record extensions present)
    if font_dir:
        font_files = sorted([p.name for p in font_dir.iterdir() if p.is_file()])
        info["font_files"] = font_files
    else:
        info["font_files"] = []

    # package.json version (sanity check vs directory name)
    info["package_version"] = pkg_version(release_dir)

    # Banner from up to 4 representative CSS files (root + minified)
    banners: dict[str, str] = {}
    if css_dir:
        for fname in ("all.css", "fontawesome.css", "font-awesome.css", "all.min.css"):
            p = css_dir / fname
            if p.exists():
                b = read_banner(p)
                if b:
                    banners[fname] = b
    info["banners"] = banners

    # CSS class prefixes used in stylesheet body (top 40 by frequency in all.css/font-awesome.css)
    candidate_main = None
    if css_dir:
        for fname in ("all.css", "fontawesome.css", "font-awesome.css"):
            p = css_dir / fname
            if p.exists():
                candidate_main = p
                break
    if candidate_main:
        body = candidate_main.read_text(encoding="utf-8", errors="replace")
        classes = Counter(CSS_CLASS_RX.findall(body))
        # Keep only classes that look like FA prefixes/short tokens
        info["top_classes"] = [
            {"class": c, "count": n}
            for c, n in classes.most_common(30)
        ]
        # Specifically extract FA family/style indicator classes
        family_indicators = sorted(
            c for c in classes
            if c in ("fa", "fas", "far", "fab", "fal", "fad", "fat",
                     "fa-solid", "fa-regular", "fa-brands", "fa-light",
                     "fa-thin", "fa-duotone", "fa-sharp")
        )
        info["family_class_indicators"] = family_indicators
    else:
        info["top_classes"] = []
        info["family_class_indicators"] = []

    return info


def main() -> int:
    out: dict = {"releases": {}}
    for ver, path in RELEASES.items():
        out["releases"][ver] = catalog_release(ver, path)

    OUT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = ["# FA source artifact inventory", "",
             "Inventory of version-bearing artifacts across FA release tarballs.",
             "Rules in rules.json MUST cite these as the source of truth.",
             ""]
    for ver, info in out["releases"].items():
        lines.append(f"## v{ver}")
        if not info.get("exists"):
            lines.append(f"- not extracted: `{info['path']}`")
            continue
        lines.append(f"- package.json version: `{info.get('package_version')}`")
        lines.append(f"- css dir: `{info.get('css_dir')}`")
        lines.append(f"- font dir: `{info.get('font_dir')}`")
        lines.append("")
        lines.append("**CSS filenames:**")
        for f in info["css_files"][:50]:
            lines.append(f"  - `{f}`")
        if len(info["css_files"]) > 50:
            lines.append(f"  - ... ({len(info['css_files']) - 50} more)")
        lines.append("")
        lines.append("**Webfont filenames:**")
        for f in info["font_files"][:30]:
            lines.append(f"  - `{f}`")
        if len(info["font_files"]) > 30:
            lines.append(f"  - ... ({len(info['font_files']) - 30} more)")
        lines.append("")
        lines.append("**Banner samples:**")
        for fname, b in info.get("banners", {}).items():
            lines.append(f"  - `{fname}`: `{b[:200]}`")
        lines.append("")
        lines.append(f"**FA family class indicators present:** `{info.get('family_class_indicators')}`")
        lines.append("")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT_JSON}")
    print(f"wrote {OUT_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
