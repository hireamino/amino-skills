#!/usr/bin/env python3
"""Prove WHI-176 Step 1b changes only the reviewed contract surfaces."""

from collections import Counter
import copy
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
BASE = "2a9c4eb3d2b53c6207d92f08bb6ab31af0a2d578"
REVISION_BASE = "edba29efb8bc3f2c04e1ee396df87ea595768ddc"
FIXTURES_PATH = "conformance/fixtures.json"
TABLE_PATH = "conformance/address-contract.json"
ORIGINAL_FIXTURE_COUNT = 45
EXPECTED_NEW_FIXTURES = (
    "robots-address-lookup-failed",
    "mta-sts-policy-host-no-address",
)
EXPECTED_NEW_FIXTURE_DIGESTS = {
    "robots-address-lookup-failed":
        "df93d7e6b77e14da5b97c936ad6e6917faa2953bb04ab1228cf46da93eb0cd59",
    "mta-sts-policy-host-no-address":
        "531d0df11fa8493aa53ade8a80ed6e91bce77342e41afff54253b7fc15ba60b5",
}
EXPECTED_ROBOTS_FLIPS = (
    "dkim-revoked-empty-p", "dkim-ed25519-badlen", "dkim-rsa-good",
    "dkim-rsa1024-weak", "dmarc-banana-invalid", "dmarc-uppercase-tags",
    "dmarc-none-monitor", "dmarc-multiple-void", "dmarc-subdomain-treewalk",
    "spf-dash-all-uppercase", "spf-over-10-lookups", "dane-unvalidated-tlsa",
    "dane-validated-tlsa", "dnssec-signed-zonecut", "dnssec-unsigned",
    "null-mx-not-applicable", "no-mx-not-exempt", "bimi-present-without-vmc",
    "ambiguous-null-mx-not-exempt", "mta-sts-lookup-servfail",
    "mta-sts-lookup-refused", "mta-sts-lookup-nxdomain-control",
    "mta-sts-lookup-servfail-null-mx", "mta-sts-null-mx-with-txt",
)


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


def normalized_fixture_document(document, undo_observation_split=False):
    """Normalize the reviewed RDAP storage re-key without hiding other changes."""
    normalized = copy.deepcopy(document)
    for fixture in normalized["fixtures"]:
        http = fixture.get("input", {}).get("http", {})
        if "rdap" in http:
            rdap = http["rdap"]
            if rdap == "unavailable":
                http["rdap"] = None
            elif isinstance(rdap, dict):
                extras = {
                    key: value for key, value in rdap.items()
                    if key not in {"status", "body", "data"}
                }
                http["rdap"] = {
                    "status": rdap.get("status"),
                    "body": rdap.get("body"),
                    "data": rdap.get("data", extras or None),
                }
        if undo_observation_split and fixture["id"] in EXPECTED_ROBOTS_FLIPS:
            fixture["expect"]["observations"]["robots"] = "unavailable"
    return normalized


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
    revision_fixture_document = json.loads(subprocess.run(
        ["git", "show", f"{REVISION_BASE}:{FIXTURES_PATH}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout)
    new_fixture_source = (ROOT / FIXTURES_PATH).read_text(encoding="utf-8")
    new_fixture_document = json.loads(new_fixture_source)
    new_existing_document = copy.deepcopy(new_fixture_document)
    new_existing_document["fixtures"] = new_existing_document["fixtures"][
        :ORIGINAL_FIXTURE_COUNT
    ]
    fixture_changes = list(changes(old_fixture_document, new_existing_document))
    old_ids = [fixture["id"] for fixture in old_fixture_document["fixtures"]]
    new_ids = [fixture["id"] for fixture in new_fixture_document["fixtures"]]
    revision_existing_changes = list(changes(
        revision_fixture_document, new_existing_document,
    ))
    if revision_existing_changes:
        for path, old, new in revision_existing_changes:
            print(
                f"UNEXPECTED_REVISION_EXISTING_FIXTURE_CHANGE {path}: "
                f"{old!r} -> {new!r}",
                file=sys.stderr,
            )
        return 1
    added_fixtures = new_fixture_document["fixtures"][ORIGINAL_FIXTURE_COUNT:]
    added_ids = tuple(fixture["id"] for fixture in added_fixtures)
    if new_ids[:ORIGINAL_FIXTURE_COUNT] != old_ids or added_ids != EXPECTED_NEW_FIXTURES:
        print(
            "UNEXPECTED_FIXTURE_IDS existing="
            + ",".join(new_ids[:ORIGINAL_FIXTURE_COUNT])
            + " added=" + ",".join(added_ids),
            file=sys.stderr,
        )
        return 1
    added_digests = {
        fixture["id"]: hashlib.sha256(canonical(fixture)).hexdigest()
        for fixture in added_fixtures
    }
    if added_digests != EXPECTED_NEW_FIXTURE_DIGESTS:
        print(
            f"UNEXPECTED_NEW_FIXTURE_CHANGE expected={EXPECTED_NEW_FIXTURE_DIGESTS} "
            f"got={added_digests}",
            file=sys.stderr,
        )
        return 1
    normalized_old = normalized_fixture_document(old_fixture_document)
    normalized_new = normalized_fixture_document(
        new_existing_document, undo_observation_split=True,
    )
    normalized_changes = list(changes(normalized_old, normalized_new))
    actual_flips = set()
    old_by_id = {fixture["id"]: fixture for fixture in old_fixture_document["fixtures"]}
    for fixture in new_fixture_document["fixtures"]:
        fixture_id = fixture["id"]
        if fixture_id not in old_by_id:
            continue
        old_observations = old_by_id[fixture_id].get("expect", {}).get("observations")
        new_observations = fixture.get("expect", {}).get("observations")
        if old_observations is None and new_observations is None:
            continue
        old_state = old_observations["robots"]
        new_state = new_observations["robots"]
        if old_state != new_state:
            if (old_state, new_state) != ("unavailable", "not_applicable"):
                normalized_changes.append(
                    ((fixture_id, "expect", "observations", "robots"), old_state, new_state)
                )
            actual_flips.add(fixture_id)
    expected_flips = set(EXPECTED_ROBOTS_FLIPS)
    if actual_flips != expected_flips:
        normalized_changes.append((
            ("robots_flip_set",), sorted(expected_flips), sorted(actual_flips),
        ))
    changed_keys = Counter(path[-1] for path, _old, _new in fixture_changes)
    rdap_changes = sum(
        len(path) >= 5 and path[0] == "fixtures"
        and path[2:5] == ("input", "http", "rdap")
        for path, _old, _new in fixture_changes
    )
    fixture_digest = hashlib.sha256(new_fixture_source.encode()).hexdigest()
    print(
        f"FIXTURE_CHANGE_PROOF fixtures={len(new_fixture_document['fixtures'])} "
        f"existing_unchanged={ORIGINAL_FIXTURE_COUNT} added={len(added_fixtures)} "
        f"changed_keys={len(fixture_changes)} keys={shown_counts(changed_keys)} "
        f"robots_flips={len(actual_flips)} rdap_rekeys={rdap_changes} "
        f"sha256={fixture_digest}"
    )
    print(
        "NEW_FIXTURE_DIGESTS "
        + ",".join(f"{key}:{added_digests[key]}" for key in EXPECTED_NEW_FIXTURES)
    )
    print(
        f"LANE_COUNTS_BEFORE {shown_counts(lane_counts(old_fixture_document))}"
    )
    print(
        f"LANE_COUNTS_AFTER_EXISTING {shown_counts(lane_counts(new_existing_document))}"
    )
    print(
        f"LANE_COUNTS_ADDED {shown_counts(lane_counts({'fixtures': added_fixtures}))}"
    )
    if lane_counts(old_fixture_document) != lane_counts(new_existing_document):
        print("UNEXPECTED_LANE_COUNT_CHANGE", file=sys.stderr)
        return 1
    if normalized_changes:
        for path, old, new in normalized_changes:
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
        revision_repository = temporary / "revision"
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
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT),
             str(revision_repository)],
            check=True,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", REVISION_BASE],
            cwd=revision_repository,
            check=True,
        )
        shutil.copytree(ROOT, new_repository, ignore=ignore)
        old_snapshot = snapshot_subprocess(old_repository)
        revision_snapshot = snapshot_subprocess(revision_repository)
        new_snapshot = snapshot_subprocess(new_repository)

    revision_output_changes = list(changes(
        json.loads(revision_snapshot), json.loads(new_snapshot),
    ))
    print(
        "REVISION_EXISTING_PRESERVATION "
        f"fixtures={len(json.loads(new_snapshot))} "
        f"changed_keys={len(revision_output_changes)} "
        f"sha256={hashlib.sha256(new_snapshot).hexdigest()}"
    )
    if revision_output_changes:
        for path, old, new in revision_output_changes:
            print(
                f"UNEXPECTED_REVISION_OUTPUT_CHANGE {path}: {old!r} -> {new!r}",
                file=sys.stderr,
            )
        return 1

    old_outputs = json.loads(old_snapshot)
    new_outputs = json.loads(new_snapshot)
    output_changes = list(changes(old_outputs, new_outputs))
    invalid_output_changes = []
    changed_fixtures = set()
    for path, old, new in output_changes:
        valid_path = (
            len(path) == 4
            and isinstance(path[0], str)
            and path[1] == "result"
            and path[2] == "observations"
            and path[3] == "robots"
            and path[0] in EXPECTED_ROBOTS_FLIPS
            and old == "unavailable"
            and new == "not_applicable"
        )
        if not valid_path:
            invalid_output_changes.append((path, old, new))
            continue
        changed_fixtures.add(path[0])
    output_keys = Counter(path[-1] for path, _old, _new in output_changes)
    digest = hashlib.sha256(new_snapshot).hexdigest()
    print(
        f"PRESERVATION fixtures={len(new_outputs)} "
        f"changed_fixtures={len(changed_fixtures)} changed_keys={len(output_changes)} "
        f"keys={shown_counts(output_keys)} "
        f"sha256={digest}"
    )
    if invalid_output_changes:
        for path, old, new in invalid_output_changes:
            print(f"UNEXPECTED_OUTPUT_CHANGE {path}: {old!r} -> {new!r}", file=sys.stderr)
        return 1
    if changed_fixtures != set(EXPECTED_ROBOTS_FLIPS):
        print(
            "UNEXPECTED_OUTPUT_FLIP_SET expected="
            + ",".join(EXPECTED_ROBOTS_FLIPS)
            + " got=" + ",".join(sorted(changed_fixtures)),
            file=sys.stderr,
        )
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
