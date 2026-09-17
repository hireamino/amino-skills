#!/usr/bin/env python3
"""Prove existing contract-fixture outputs are unchanged from the reviewed base."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BASE = "34a8fcb35f40ef4340b67be8f95f05ca6a3839e5"
FIXTURES_PATH = "conformance/fixtures.json"
TABLE_PATH = "conformance/address-contract.json"
PROTECTED_PATHS = ("conformance/run.mjs", "conformance/canary.mjs")
ORIGINAL_FIXTURE_COUNT = 45


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()


def raw_fixture_objects(source):
    """Return each fixture object's exact source bytes, without JSON reserialization."""
    marker = '"fixtures": ['
    position = source.index(marker) + len(marker)
    objects = []
    while position < len(source):
        while position < len(source) and source[position] in " \t\r\n,":
            position += 1
        if position >= len(source) or source[position] == "]":
            break
        if source[position] != "{":
            raise ValueError(f"unexpected fixture token at offset {position}")
        start = position
        depth = 0
        quoted = escaped = False
        while position < len(source):
            character = source[position]
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    position += 1
                    objects.append(source[start:position].encode())
                    break
            position += 1
    return objects


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
    old_fixture_objects = raw_fixture_objects(old_fixtures_source)
    new_fixture_objects = raw_fixture_objects(
        (ROOT / FIXTURES_PATH).read_text(encoding="utf-8")
    )
    changed_fixture_bytes = [
        index for index, old_object in enumerate(old_fixture_objects)
        if old_object != new_fixture_objects[index]
    ]
    fixture_bytes = b"\0".join(new_fixture_objects[:ORIGINAL_FIXTURE_COUNT])
    fixture_digest = hashlib.sha256(fixture_bytes).hexdigest()
    print(
        f"FIXTURE_BYTES objects={len(old_fixture_objects)} "
        f"changed={len(changed_fixture_bytes)} sha256={fixture_digest}"
    )
    if changed_fixture_bytes:
        print(
            "CHANGED_FIXTURE_BYTES " + ",".join(map(str, changed_fixture_bytes)),
            file=sys.stderr,
        )
        return 1

    old_table = json.loads(subprocess.run(
        ["git", "show", f"{BASE}:{TABLE_PATH}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout)
    new_table = json.loads((ROOT / TABLE_PATH).read_text(encoding="utf-8"))
    protected_table_fields = (
        "ipv4NonPublic", "ipv6PublicWithin",
        "ipv6NonPublicWithinPublic", "ipv4MappedWithin",
    )
    table_fields_unchanged = all(
        old_table[field] == new_table[field] for field in protected_table_fields
    )
    old_rows_unchanged = (
        len(old_table["rows"]) == 114
        and new_table["rows"][:114] == old_table["rows"]
    )
    print(
        "ADDRESS_TABLE_PRESERVATION "
        f"networks={'unchanged' if table_fields_unchanged else 'changed'} "
        f"old_rows={'unchanged' if old_rows_unchanged else 'changed'} "
        f"old={len(old_table['rows'])} new={len(new_table['rows'])}"
    )
    if not table_fields_unchanged or not old_rows_unchanged:
        return 1

    for protected_path in PROTECTED_PATHS:
        old_bytes = subprocess.run(
            ["git", "show", f"{BASE}:{protected_path}"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
        new_bytes = (ROOT / protected_path).read_bytes()
        unchanged = old_bytes == new_bytes
        print(
            f"PROTECTED_BYTES path={protected_path} "
            f"unchanged={str(unchanged).lower()} "
            f"sha256={hashlib.sha256(new_bytes).hexdigest()}"
        )
        if not unchanged:
            return 1

    with tempfile.TemporaryDirectory(prefix="amino-whi127-preservation-") as temporary:
        temporary = Path(temporary)
        old_repository = temporary / "old"
        new_repository = temporary / "new"
        ignore = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".DS_Store")
        archive = subprocess.run(
            ["git", "archive", BASE],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
        old_repository.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(old_repository, filter="data")
        shutil.copytree(ROOT, new_repository, ignore=ignore)
        old_snapshot = snapshot_subprocess(old_repository)
        new_snapshot = snapshot_subprocess(new_repository)

    old_outputs = json.loads(old_snapshot)
    new_outputs = json.loads(new_snapshot)
    changed = [
        fixture_id for fixture_id in old_outputs
        if old_outputs[fixture_id] != new_outputs.get(fixture_id)
    ]
    digest = hashlib.sha256(new_snapshot).hexdigest()
    print(
        f"PRESERVATION fixtures={len(new_outputs)} changed={len(changed)} "
        f"sha256={digest}"
    )
    if changed:
        print("CHANGED " + ",".join(changed), file=sys.stderr)
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
