#!/usr/bin/env python3
"""WHI-215 Step 2a: prove existing reviewed rows and Python outputs are preserved.

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
BASE = "e61b74ebe84116f30eb24aa70db64e81ab1db9c7"
FIXTURES_PATH = "conformance/fixtures.json"
TABLE_PATH = "conformance/address-contract.json"
NEW_IDS = (
    "registrable-root-nhs-uk",
    "registrable-root-sch-uk-wildcard",
    "registrable-root-police-uk",
    "registrable-root-gov-uk",
    "registrable-root-com-es",
    "registrable-root-ac-in",
    "registrable-root-k12-us",
    "registrable-root-alabel",
)
# Deliberately re-pin only after reviewing the new fixture bodies.
NEW_DIGESTS = {
    "registrable-root-nhs-uk": "2de63b1150fb19285191641939c8b7d19d2f991c547097c3bb49e8b46110e529",
    "registrable-root-sch-uk-wildcard": "b88cc4ebae3b41aa840e5840cede47ecbfddfbec9b9ff0be09988d973a9ff9e2",
    "registrable-root-police-uk": "db10b58effc944a11af306e423f9c943c56ae36095f9ac5805327453a45e8ee9",
    "registrable-root-gov-uk": "c06b4b1618d2a6affad8597514307c2fb3b7bbeff3f16c68d223c54fb3db0e87",
    "registrable-root-com-es": "d990830915197d9576b662a8d47a6e137eab9ef75deca074802f370bf3565366",
    "registrable-root-ac-in": "f592e5f6699d225bc517520a5ff2fc2558fc2722955b8906dd4596e9b00302b2",
    "registrable-root-k12-us": "f79430eab39abac26515ba59dbd764662558ec26ad68105f0d3c62dc58c4587c",
    "registrable-root-alabel": "99ee59c04aadb99f14c783723dee18b61ae58e86bad9b01dc8cb26ff9c4ca29b",
}

OLD_RELIABILITY_REASON = (
    "Resolver-level transient detection not implemented (v1.3); the "
    "engine-exception path is covered by finalize() tests."
)
NEW_RELIABILITY_REASON = (
    "Wrapper-mode reliability placeholder: resolver-level I20 is covered by "
    "dns-engine fixtures; wrapper exception handling remains covered by "
    "consumer finalize() tests."
)


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
    if set(base_document) != set(current_document) or len(base) != 58 or len(current) != 66:
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
        expected = []
        if delta != expected:
            fixture_changes.append((old["id"], delta, expected))
    if fixture_changes:
        print(f"UNEXPECTED_EXISTING_FIXTURE_CHANGE {fixture_changes}", file=sys.stderr)
        return 1

    digests = {f["id"]: hashlib.sha256(canonical(f)).hexdigest() for f in current[len(base):]}
    if digests != NEW_DIGESTS:
        print(f"UNEXPECTED_NEW_FIXTURE_CHANGE {digests}", file=sys.stderr)
        return 1
    table_same = git_show(TABLE_PATH) == (ROOT / TABLE_PATH).read_bytes()
    print(
        f"FIXTURE_CHANGE_PROOF existing={len(base)} added={len(NEW_IDS)} "
        "allowed_existing_changes=none "
        f"address_table_unchanged={str(table_same).lower()}"
    )
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
    valid = set(current_outputs) == expected_ids and len(expected_ids) == 53 and not output_changes
    print(
        f"OUTPUT_PRESERVATION fixtures={len(current_outputs)} changed_keys={len(output_changes)} "
        f"by_key={dict(sorted(grouped.items()))} "
        f"sha256={hashlib.sha256(canonical(current_outputs)).hexdigest()}"
    )
    if not valid:
        for path, before, after in output_changes:
            print(f"UNEXPECTED_OUTPUT_CHANGE {path}: {before!r} -> {after!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
