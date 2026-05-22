import json
from collections import Counter, defaultdict

INPUT_FILE = "scan_results.jsonl"


def detect_encoding(path):
    with open(path, "rb") as f:
        start = f.read(4)

    if start.startswith(b"\xff\xfe") or start.startswith(b"\xfe\xff"):
        return "utf-16"
    elif start.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    else:
        return "utf-8"


def open_safe(path):
    encodings = [detect_encoding(path), "utf-8", "utf-8-sig", "latin-1"]

    for enc in encodings:
        try:
            return open(path, "r", encoding=enc)
        except Exception:
            continue

    raise RuntimeError("Cannot open file")


def analyze(file_obj):
    tech_counter = Counter()
    version_counter = Counter()
    tech_with_version_counter = Counter()
    tech_versions = defaultdict(list)

    # NEW
    url_version_counter = Counter()
    tech_url_map = defaultdict(set)

    total_targets = 0
    total_techs = 0
    bad_lines = 0

    for line in file_obj:
        line = line.strip()

        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            bad_lines += 1
            continue

        total_targets += 1

        techs = data.get("techs", [])
        total_techs += len(techs)

        for tech in techs:
            name = tech.get("name")
            version = tech.get("version")
            evidence = tech.get("evidence", [])

            if not name:
                continue

            name = name.lower()

            tech_counter[name] += 1

            if version:
                tech_with_version_counter[name] += 1
                version_counter[(name, version)] += 1
                tech_versions[name].append(version)

                # Extract URL from evidence
                for ev in evidence:
                    url = ev.get("url")

                    if url:
                        url_version_counter[url] += 1
                        tech_url_map[name].add(url)

    # =========================
    # OUTPUT
    # =========================

    print("=" * 60)
    print(f"Targets: {total_targets}")
    print(f"Total tech detections: {total_techs}")
    print(f"Bad lines skipped: {bad_lines}")
    print(f"Unique tech count: {len(tech_counter)}")
    print("=" * 60)

    # =========================
    # TOP TECHS
    # =========================

    print("\nTop 10 most detected tech:")
    for tech, count in tech_counter.most_common(10):
        print(f"{tech}: {count}")

    print("\nTop 10 techs WITH version:")
    for tech, count in tech_with_version_counter.most_common(10):
        print(f"{tech}: {count}")

    # =========================
    # MOST DETECTED WITHOUT VERSION
    # =========================

    print("\nTop 20 most detected techs WITHOUT version:")

    without_version_counter = []

    for tech, total in tech_counter.items():
        with_ver = tech_with_version_counter.get(tech, 0)
        without_ver = total - with_ver

        if without_ver > 0:
            without_version_counter.append((tech, without_ver))

    without_version_counter.sort(
        key=lambda x: x[1],
        reverse=True
    )

    for tech, count in without_version_counter[:20]:
        print(f"{tech}: {count}")

    # =========================
    # TOP TECH + VERSION
    # =========================

    print("\nTop 10 (tech, version):")
    for (tech, version), count in version_counter.most_common(10):
        print(f"{tech} {version}: {count}")

    # =========================
    # VERSION COVERAGE
    # =========================

    print("\nVersion coverage:")

    for tech in sorted(
        tech_counter,
        key=lambda t: -tech_counter[t]
    ):
        total = tech_counter[tech]
        with_ver = tech_with_version_counter.get(tech, 0)
        without_ver = total - with_ver

        ratio = (with_ver / total * 100) if total else 0

        print(
            f"{tech}: "
            f"with={with_ver}, "
            f"without={without_ver}, "
            f"coverage={ratio:.1f}%"
        )

    # =========================
    # TECHS WITH NO VERSION
    # =========================

    print("\nTechs NEVER detected with version:")

    for tech in sorted(
        tech_counter,
        key=lambda t: -tech_counter[t]
    ):
        if tech_with_version_counter.get(tech, 0) == 0:
            print(f"  {tech} ({tech_counter[tech]} targets)")

    # =========================
    # MULTIPLE VERSION DETECTION
    # =========================

    print("\nTechs with multiple versions:")

    for tech, versions in tech_versions.items():
        uniq = set(versions)

        if len(uniq) > 1:
            print(f"{tech}: {sorted(uniq)}")

    # =========================
    # URL VERSION LEAKS
    # =========================

    print("\nTop 50 URLs leaking version:")

    for url, count in url_version_counter.most_common(50):
        print(f"{url} -> {count} hits")

    # =========================
    # TECH -> URL SAMPLE
    # =========================

    print("\nTech -> URLs (sample):")

    for tech, urls in list(tech_url_map.items())[:10]:
        print(f"{tech}:")

        for u in list(urls)[:3]:
            print(f"  - {u}")


if __name__ == "__main__":
    f = open_safe(INPUT_FILE)

    try:
        analyze(f)
    finally:
        f.close()