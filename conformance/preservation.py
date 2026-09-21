#!/usr/bin/env python3
"""WHI-180: prove the reviewed corpus and Python output changed only at I20.

BASE is a commit, never a mutable branch. A shallow clone without BASE fails
closed at git show/checkout; the workflow fetches full history for this proof.
"""

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
BASE = "57fde17dfae2f172bd32bc0d8fc6e90f141c9cf1"
FIXTURES_PATH = "conformance/fixtures.json"
TABLE_PATH = "conformance/address-contract.json"
NEW_IDS = (
    "inconclusive-apex-txt-servfail",
    "inconclusive-dmarc-txt-refused",
    "inconclusive-apex-mx-servfail",
    "inconclusive-apex-txt-before-mx",
    "inconclusive-dmarc-nxdomain",
)
# Deliberately re-pin only after reviewing the new fixture bodies.
NEW_DIGESTS = {
    "inconclusive-apex-txt-servfail": "d492c98e261b9e677439dfe2abe05af5ee76bb39f7a279c353c88a37b748cc72",
    "inconclusive-dmarc-txt-refused": "d41bb4f50ee01eb92a9254727402752e3b036c6f793b4cf98146ac992e2b98b2",
    "inconclusive-apex-mx-servfail": "ccd8bd80688af521920b376cd461e20532345181dbd108037752419c54545581",
    "inconclusive-apex-txt-before-mx": "bfa4eb852d4fdf2a194c3c198157eb11818dc37104338933f14e563830312109",
    "inconclusive-dmarc-nxdomain": "1672a839b0c55cf7bb6f511b49c5b5ed3b1d79a9cb4e1a192400f4436cfea2d5",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def changes(old, new, path=()):
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
        for index, (left, right) in enumerate(zip(old, new)):
            yield from changes(left, right, path + (index,))
    elif old != new:
        yield path, old, new


def git_show(path):
    return subprocess.run(
        ["git", "show", f"{BASE}:{path}"], cwd=ROOT, check=True,
        capture_output=True,
    ).stdout


def snapshot(repository, count):
    conformance = repository / "conformance"
    sys.path.insert(0, str(conformance))
    spec = importlib.util.spec_from_file_location("preservation_runner", conformance / "run_py.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    fixtures = json.loads((conformance / "fixtures.json").read_text())["fixtures"][:count]
    outputs = {}
    for fixture in fixtures:
        if fixture.get("mode") not in runner.CONTRACT_MODES:
            continue
        runner.NETWORK_ATTEMPTS.clear()
        runner.HTTP_CALLS.clear()
        runner.install_resolver(fixture["input"].get("dns", {}))
        runner.install_http(fixture["input"]["domain"], fixture["input"].get("http", {}))
        now_ms = fixture["input"].get("nowMs")
        runner.audit.time.time = runner.REAL_TIME if now_ms is None else lambda: now_ms / 1000
        try:
            outputs[fixture["id"]] = {
                "result": runner.run_shipping_audit(fixture["input"]["domain"]),
                "score": runner.run_score(fixture["input"]["domain"]),
            }
        finally:
            runner.audit.time.time = runner.REAL_TIME
        if runner.NETWORK_ATTEMPTS:
            raise AssertionError(f"network attempted in {fixture['id']}: {runner.NETWORK_ATTEMPTS}")
    return outputs


def snapshot_subprocess(repository, count):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--snapshot", str(repository), str(count)],
        cwd=repository,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--snapshot":
        sys.stdout.buffer.write(canonical(snapshot(Path(sys.argv[2]).resolve(), int(sys.argv[3]))))
        return 0

    base_document = json.loads(git_show(FIXTURES_PATH))
    current_document = json.loads((ROOT / FIXTURES_PATH).read_text(encoding="utf-8"))
    base = base_document["fixtures"]
    current = current_document["fixtures"]
    if set(base_document) != set(current_document) or len(base) != 47 or len(current) != 52:
        print("UNEXPECTED_FIXTURE_SHAPE", file=sys.stderr)
        return 1
    if [f["id"] for f in current[:len(base)]] != [f["id"] for f in base]:
        print("UNEXPECTED_EXISTING_FIXTURE_ORDER", file=sys.stderr)
        return 1
    if tuple(f["id"] for f in current[len(base):]) != NEW_IDS:
        print("UNEXPECTED_NEW_FIXTURE_IDS", file=sys.stderr)
        return 1

    fixture_changes = []
    for old, new in zip(base, current):
        delta = list(changes(old, new))
        expected = (
            {("expect", "inconclusive"), ("expect", "inconclusive_reason")}
            if old.get("mode") == "dns-engine" and "inconclusive" not in old["expect"]
            else set()
        )
        actual = {path for path, _before, _after in delta}
        if actual != expected or any(
            (path == ("expect", "inconclusive") and after is not False)
            or (path == ("expect", "inconclusive_reason") and after is not None)
            for path, _before, after in delta
        ):
            fixture_changes.append((old["id"], delta, expected))
        if old.get("mode") == "dns-engine" and (
            new["expect"].get("inconclusive") is not False
            or new["expect"].get("inconclusive_reason", "MISSING") is not None
        ):
            fixture_changes.append((old["id"], "missing or incorrect I20 expectation", expected))
    if fixture_changes:
        print(f"UNEXPECTED_EXISTING_FIXTURE_CHANGE {fixture_changes}", file=sys.stderr)
        return 1

    digests = {f["id"]: hashlib.sha256(canonical(f)).hexdigest() for f in current[len(base):]}
    if digests != NEW_DIGESTS:
        print(f"UNEXPECTED_NEW_FIXTURE_CHANGE {digests}", file=sys.stderr)
        return 1
    table_same = git_show(TABLE_PATH) == (ROOT / TABLE_PATH).read_bytes()
    print(f"FIXTURE_CHANGE_PROOF existing={len(base)} dns_engine={sum(f.get('mode') == 'dns-engine' for f in base)} added={len(NEW_IDS)} only_added_keys=inconclusive,inconclusive_reason address_table_unchanged={str(table_same).lower()}")
    print("NEW_FIXTURE_DIGESTS " + ",".join(f"{key}:{digests[key]}" for key in NEW_IDS))
    if not table_same:
        return 1

    with tempfile.TemporaryDirectory(prefix="amino-whi180-preservation-") as temporary:
        old_repository = Path(temporary) / "base"
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT), str(old_repository)],
            check=True,
        )
        subprocess.run(["git", "checkout", "--quiet", BASE], cwd=old_repository, check=True)
        old_outputs = snapshot_subprocess(old_repository, len(base))
        current_outputs = snapshot_subprocess(ROOT, len(base))

    output_changes = list(changes(old_outputs, current_outputs))
    grouped = Counter(path[-1] for path, _before, _after in output_changes)
    expected_ids = set(old_outputs)
    valid = (
        set(current_outputs) == expected_ids
        and len(expected_ids) == 42
        and grouped == {"inconclusive": 42, "inconclusive_reason": 42}
        and all(
            path == (fixture_id, "result", field)
            and (after is False if field == "inconclusive" else after is None)
            for path, _before, after in output_changes
            for fixture_id, field in [(path[0], path[-1])]
        )
    )
    print(
        f"OUTPUT_PRESERVATION fixtures={len(current_outputs)} changed_keys={len(output_changes)} "
        f"by_key={dict(sorted(grouped.items()))} "
        f"sha256={hashlib.sha256(canonical(current_outputs)).hexdigest()}"
    )
    if not valid:
        for path, before, after in output_changes:
            if path[1:] not in {("result", "inconclusive"), ("result", "inconclusive_reason")}:
                print(f"UNEXPECTED_OUTPUT_CHANGE {path}: {before!r} -> {after!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
