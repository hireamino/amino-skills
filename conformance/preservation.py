#!/usr/bin/env python3
"""Prove WHI-176 changes only reviewed finding-lane values from its base."""

from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BASE = "59b8a630884e8c3ea992e2a521056c968caa789d"
FIXTURES_PATH = "conformance/fixtures.json"
TABLE_PATH = "conformance/address-contract.json"
ORIGINAL_FIXTURE_COUNT = 45
MOVED_AREA_LANES = {
    "CAA": "brand_optional",
    "DNSSEC": "outside_sending_posture",
    "Reputation": "outside_sending_posture",
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()


def changes(old, new, path=()):
    """Yield every semantic leaf change with its path."""
    if type(old) is not type(new):
        yield path, old, new
    elif isinstance(old, dict):
        for key in sorted(set(old) | set(new)):
            if key not in old or key not in new:
                yield path + (key,), old.get(key), new.get(key)
            else:
                yield from changes(old[key], new[key], path + (key,))
    elif isinstance(old, list):
        if len(old) != len(new):
            yield path + ("length",), len(old), len(new)
        for index, (old_item, new_item) in enumerate(zip(old, new)):
            yield from changes(old_item, new_item, path + (index,))
    elif old != new:
        yield path, old, new


def lane_counts(document):
    return Counter(
        finding["lane"]
        for fixture in document["fixtures"]
        for finding in fixture.get("expect", {}).get("findings", [])
    )


def shown_counts(counts):
    return ",".join(f"{key}:{counts[key]}" for key in sorted(counts))


def snapshot(repository):
    conformance = repository / "conformance"
    sys.path.insert(0, str(conformance))
    spec = importlib.util.spec_from_file_location(
        "whi127_preservation_runner", conformance / "run_py.py",
    )
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    fixtures = json.loads(
        (conformance / "fixtures.json").read_text(encoding="utf-8")
    )["fixtures"][:ORIGINAL_FIXTURE_COUNT]
    outputs = {}
    for fixture in fixtures:
        if fixture.get("mode") not in runner.CONTRACT_MODES:
            continue
        runner.NETWORK_ATTEMPTS.clear()
        runner.HTTP_CALLS.clear()
        runner.install_resolver(fixture["input"].get("dns", {}))
        runner.install_http(
            fixture["input"]["domain"], fixture["input"].get("http", {}),
        )
        now_ms = fixture["input"].get("nowMs")
        runner.audit.time.time = (
            runner.REAL_TIME if now_ms is None else lambda: now_ms / 1000
        )
        try:
            outputs[fixture["id"]] = {
                "result": runner.run_shipping_audit(fixture["input"]["domain"]),
                "score": runner.run_score(fixture["input"]["domain"]),
            }
        finally:
            runner.audit.time.time = runner.REAL_TIME
    return outputs


def snapshot_subprocess(repository):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()),
         "--snapshot", str(repository)],
        cwd=repository,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.encode()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--snapshot":
        sys.stdout.buffer.write(canonical(snapshot(Path(sys.argv[2]).resolve())))
        return 0

    old_fixtures_source = subprocess.run(
        ["git", "show", f"{BASE}:{FIXTURES_PATH}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    old_fixture_document = json.loads(old_fixtures_source)
    new_fixture_source = (ROOT / FIXTURES_PATH).read_text(encoding="utf-8")
    new_fixture_document = json.loads(new_fixture_source)
    fixture_changes = list(changes(old_fixture_document, new_fixture_document))
    changed_areas = Counter()
    invalid_fixture_changes = []
    for path, old, new in fixture_changes:
        valid_path = (
            len(path) == 6
            and path[0] == "fixtures"
            and isinstance(path[1], int)
            and path[2] == "expect"
            and path[3] == "findings"
            and isinstance(path[4], int)
            and path[5] == "lane"
        )
        if not valid_path:
            invalid_fixture_changes.append((path, old, new))
            continue
        finding = old_fixture_document["fixtures"][path[1]]["expect"]["findings"][path[4]]
        area = finding.get("area")
        if area not in MOVED_AREA_LANES or old != MOVED_AREA_LANES[area] or new != "domain_posture":
            invalid_fixture_changes.append((path, old, new))
            continue
        changed_areas[area] += 1
    changed_keys = Counter(path[-1] for path, _old, _new in fixture_changes)
    fixture_digest = hashlib.sha256(new_fixture_source.encode()).hexdigest()
    print(
        f"FIXTURE_CHANGE_PROOF fixtures={len(new_fixture_document['fixtures'])} "
        f"changed_keys={len(fixture_changes)} keys={shown_counts(changed_keys)} "
        f"areas={shown_counts(changed_areas)} sha256={fixture_digest}"
    )
    print(
        f"LANE_COUNTS_BEFORE {shown_counts(lane_counts(old_fixture_document))}"
    )
    print(
        f"LANE_COUNTS_AFTER {shown_counts(lane_counts(new_fixture_document))}"
    )
    if invalid_fixture_changes:
        for path, old, new in invalid_fixture_changes:
            print(f"UNEXPECTED_FIXTURE_CHANGE {path}: {old!r} -> {new!r}", file=sys.stderr)
        return 1

    old_table = json.loads(subprocess.run(
        ["git", "show", f"{BASE}:{TABLE_PATH}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout)
    new_table = json.loads((ROOT / TABLE_PATH).read_text(encoding="utf-8"))
    table_unchanged = old_table == new_table
    print(
        "ADDRESS_TABLE_PRESERVATION "
        f"unchanged={str(table_unchanged).lower()} "
        f"old={len(old_table['rows'])} new={len(new_table['rows'])}"
    )
    if not table_unchanged:
        return 1

    with tempfile.TemporaryDirectory(prefix="amino-whi127-preservation-") as temporary:
        temporary = Path(temporary)
        old_repository = temporary / "old"
        new_repository = temporary / "new"
        ignore = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".DS_Store")
        # Clone the local object database and check out the reviewed commit instead
        # of unpacking an archive. A shallow checkout that lacks BASE therefore fails
        # closed at checkout, and neither archive paths nor external network are used.
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT), str(old_repository)],
            check=True,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", BASE],
            cwd=old_repository,
            check=True,
        )
        shutil.copytree(ROOT, new_repository, ignore=ignore)
        old_snapshot = snapshot_subprocess(old_repository)
        new_snapshot = snapshot_subprocess(new_repository)

    old_outputs = json.loads(old_snapshot)
    new_outputs = json.loads(new_snapshot)
    output_changes = list(changes(old_outputs, new_outputs))
    invalid_output_changes = []
    changed_fixtures = set()
    changed_output_areas = Counter()
    for path, old, new in output_changes:
        valid_path = (
            len(path) == 5
            and isinstance(path[0], str)
            and path[1] == "result"
            and path[2] == "findings"
            and isinstance(path[3], int)
            and path[4] == "lane"
        )
        if not valid_path:
            invalid_output_changes.append((path, old, new))
            continue
        old_finding = old_outputs[path[0]]["result"]["findings"][path[3]]
        new_finding = new_outputs[path[0]]["result"]["findings"][path[3]]
        area = old_finding.get("area")
        if (
            area not in MOVED_AREA_LANES
            or new_finding.get("area") != area
            or old != MOVED_AREA_LANES[area]
            or new != "domain_posture"
        ):
            invalid_output_changes.append((path, old, new))
            continue
        changed_fixtures.add(path[0])
        changed_output_areas[area] += 1
    output_keys = Counter(path[-1] for path, _old, _new in output_changes)
    digest = hashlib.sha256(new_snapshot).hexdigest()
    print(
        f"PRESERVATION fixtures={len(new_outputs)} "
        f"changed_fixtures={len(changed_fixtures)} changed_keys={len(output_changes)} "
        f"keys={shown_counts(output_keys)} areas={shown_counts(changed_output_areas)} "
        f"sha256={digest}"
    )
    if invalid_output_changes:
        for path, old, new in invalid_output_changes:
            print(f"UNEXPECTED_OUTPUT_CHANGE {path}: {old!r} -> {new!r}", file=sys.stderr)
        return 1
    if len(new_outputs) != 40:
        print(
            f"expected 40 original contract fixtures, got {len(new_outputs)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
