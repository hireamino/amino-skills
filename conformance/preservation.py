#!/usr/bin/env python3
"""Bound the deliberate reviewed corpus and output-contract changes.

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
BASE = "ef557911d381073991ba907f46c2e67c1780ba24"
FIXTURES_PATH = "conformance/fixtures.json"
TABLE_PATH = "conformance/address-contract.json"
NEW_IDS = (
    "dmarc-parent-psd-y-sp-reject",
    "dmarc-parent-psd-y-sp-none",
    "dmarc-parent-psd-y-np-reject",
    "dmarc-parent-none-above-root",
    "dmarc-parent-psd-u-before-psd-y",
    "dmarc-parent-psd-y-existence-failure",
    "dmarc-parent-tld-psd-y-sp-none",
    "dmarc-parent-tld-psd-y-np-reject",
)
WHI254_NEW_IDS = (
    "mx-provider-psl-distinct",
    "mx-provider-psl-same",
    "dmarc-external-null-organizations",
)
CHANGED_IDS = (
    "registrable-root-nhs-uk",
    "registrable-root-sch-uk-wildcard",
    "registrable-root-police-uk",
    "registrable-root-gov-uk",
    "registrable-root-com-es",
    "registrable-root-ac-in",
    "registrable-root-k12-us",
    "registrable-root-alabel",
)
WHI280_CHANGED_IDS = (
    "inconclusive-apex-txt-servfail",
    "inconclusive-dmarc-txt-refused",
    "inconclusive-apex-mx-servfail",
    "inconclusive-apex-txt-before-mx",
    "inconclusive-apex-txt-notimp",
    "inconclusive-dmarc-txt-formerr",
    "inconclusive-apex-mx-notimp",
)
WHI280_MARKERS = {
    "inconclusive-apex-txt-servfail": {
        ("SPF", "No SPF record"): "TXT ex.com: SERVFAIL/REFUSED",
    },
    "inconclusive-dmarc-txt-refused": {
        ("DMARC", "No DMARC record"): "TXT _dmarc.ex.com: SERVFAIL/REFUSED",
    },
    "inconclusive-apex-mx-servfail": {
        ("Transport", "No MX records"): "MX ex.com: SERVFAIL/REFUSED",
        ("MTA-STS", "No MTA-STS policy"): "MX ex.com: SERVFAIL/REFUSED",
        ("TLS-RPT", "No TLS-RPT"): "MX ex.com: SERVFAIL/REFUSED",
    },
    "inconclusive-apex-txt-before-mx": {
        ("SPF", "No SPF record"): "TXT ex.com: SERVFAIL/REFUSED",
        ("Transport", "No MX records"): "MX ex.com: SERVFAIL/REFUSED",
        ("MTA-STS", "No MTA-STS policy"): "MX ex.com: SERVFAIL/REFUSED",
        ("TLS-RPT", "No TLS-RPT"): "MX ex.com: SERVFAIL/REFUSED",
    },
    "inconclusive-apex-txt-notimp": {
        ("SPF", "No SPF record"): "TXT ex.com: lookup error",
    },
    "inconclusive-dmarc-txt-formerr": {
        ("DMARC", "No DMARC record"): "TXT _dmarc.ex.com: lookup error",
    },
    "inconclusive-apex-mx-notimp": {
        ("Transport", "No MX records"): "MX ex.com: lookup error",
        ("MTA-STS", "No MTA-STS policy"): "MX ex.com: lookup error",
        ("TLS-RPT", "No TLS-RPT"): "MX ex.com: lookup error",
    },
}
NEW_DIGESTS = {
    "dmarc-parent-psd-y-sp-reject": "8b82ccc8ce6664e0d44f6269bbc8438bba40f8c2b0e3ed2d550f52b66844ad1d",
    "dmarc-parent-psd-y-sp-none": "114762297afbc90c9d4f4794b84b4d49abbf4bfbe43b89137e718d07babd3bfc",
    "dmarc-parent-psd-y-np-reject": "a4ca274aea02511dec85e87ab8dc61ec7a19d6a7c0f92ddcb59047cfd9795480",
    "dmarc-parent-none-above-root": "776df7d946f76d1aa68a30b8000fc7fd27e42999021ceb0fc84c7df6290bb616",
    "dmarc-parent-psd-u-before-psd-y": "12edf723c91ee22d6f72a8c948df070ca0ac4ee25712297bcb8c7a101b3be0e1",
    "dmarc-parent-psd-y-existence-failure": "88ae193e48a1b79db642c49da2ba5132f72bc3ddb0ab85fb11ec94e364111977",
    "dmarc-parent-tld-psd-y-sp-none": "2a835472673b2381961b4f529f331d3a5343ffe3f94ebea3a3353ee21f8bb035",
    "dmarc-parent-tld-psd-y-np-reject": "2765334d1733385cb246704a4935066bd4904f2c8efc7bc67615728c1498f45f",
}
WHI254_NEW_DIGESTS = {
    "mx-provider-psl-distinct": "60b65cbf98a2d4a9fe297923e9edefe2e8c3961a29db2fe7b8b53482b4d2c80a",
    "mx-provider-psl-same": "c708fd612405f8d2027a7bf83095c099292c72a5f58c6eb12a8e1a60bcfd9d63",
    "dmarc-external-null-organizations": "ae6121f6e7f76058d239b051175d42378e3c7b6418dc7243055bfe92a42f4146",
}
CHANGED_DIGESTS = {
    "registrable-root-nhs-uk": "2a0c85be080fae66392e177b9c9de70a0a9f3e5f80f3974718657239541faec4",
    "registrable-root-sch-uk-wildcard": "affc8e1485291c19a32fc31749fa805c071188b1fd2820873b2dc9f7afd15fec",
    "registrable-root-police-uk": "bb70a82644d7abf19a3df31a8c003e31e30a5d4388ca2ac40a12d7912cbd8209",
    "registrable-root-gov-uk": "cf72327eab49c23c779750163fc6210c7c4a1d8839a4e8a316974a0d8a2354cf",
    "registrable-root-com-es": "f55a272c8d42c35542a73d45207d9c49f1f97ec91918ac066c03df3f266f0a93",
    "registrable-root-ac-in": "f0fbcad11c879e93738f644f408b3cb94eb1325ca084dade9ba9c8a496334b04",
    "registrable-root-k12-us": "f83018290dbfa31e4ae61752f2ee8e1938bdd52547348bf9c23ba8a949fe0143",
    "registrable-root-alabel": "d33ecbfa04cf2b8ee6425a78332d060cc1322735bceed88ba1e0ad0993ad16ce",
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


def snapshot(repository, included_ids):
    conformance = repository / "conformance"
    sys.path.insert(0, str(conformance))
    spec = importlib.util.spec_from_file_location("preservation_runner", conformance / "run_py.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    fixtures = json.loads((conformance / "fixtures.json").read_text())["fixtures"]
    outputs = {}
    for fixture in fixtures:
        if fixture["id"] not in included_ids:
            continue
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


def snapshot_subprocess(repository, included_ids):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--snapshot", str(repository), json.dumps(sorted(included_ids))],
        cwd=repository,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--snapshot":
        sys.stdout.buffer.write(canonical(snapshot(Path(sys.argv[2]).resolve(), set(json.loads(sys.argv[3])))))
        return 0

    base_document = json.loads(git_show(FIXTURES_PATH))
    current_document = json.loads((ROOT / FIXTURES_PATH).read_text(encoding="utf-8"))
    base = base_document["fixtures"]
    current = current_document["fixtures"]
    if set(base_document) != set(current_document) or len(base) != 66 or len(current) != 77:
        print("UNEXPECTED_FIXTURE_SHAPE", file=sys.stderr)
        return 1
    if [f["id"] for f in current[:len(base)]] != [f["id"] for f in base]:
        print("UNEXPECTED_EXISTING_FIXTURE_ORDER", file=sys.stderr)
        return 1
    if tuple(f["id"] for f in current[len(base):]) != NEW_IDS + WHI254_NEW_IDS:
        print("UNEXPECTED_NEW_FIXTURE_IDS", file=sys.stderr)
        return 1

    fixture_changes = []
    for old, new in zip(base, current):
        candidate = json.loads(json.dumps(new))
        if old["id"] in CHANGED_IDS:
            findings = candidate["expect"]["findings"]
            candidate["expect"]["findings"] = [
                finding for finding in findings
                if finding["title"] != "Parent DMARC record observed above registrable root"
            ]
            if len(candidate["expect"]["findings"]) != len(findings) - 1:
                fixture_changes.append((old["id"], "missing one parent observation"))
        if old["id"] in WHI280_CHANGED_IDS:
            findings = candidate["expect"]["findings"]
            actual_markers = {
                (finding["area"], finding["title"]): finding["unconfirmed"]
                for finding in findings if "unconfirmed" in finding
            }
            if actual_markers != WHI280_MARKERS[old["id"]]:
                fixture_changes.append((old["id"], {
                    "unconfirmed": actual_markers,
                    "expected": WHI280_MARKERS[old["id"]],
                }))
            for finding in findings:
                finding.pop("unconfirmed", None)
        delta = list(changes(old, candidate))
        if delta:
            fixture_changes.append((old["id"], delta))
    if fixture_changes:
        print(f"UNEXPECTED_EXISTING_FIXTURE_CHANGE {fixture_changes}", file=sys.stderr)
        return 1

    current_by_id = {fixture["id"]: fixture for fixture in current}
    digests = {
        f["id"]: hashlib.sha256(canonical(f)).hexdigest()
        for f in current[len(base):len(base) + len(NEW_IDS)]
    }
    if digests != NEW_DIGESTS:
        print(f"UNEXPECTED_NEW_FIXTURE_CHANGE {digests}", file=sys.stderr)
        return 1
    table_same = git_show(TABLE_PATH) == (ROOT / TABLE_PATH).read_bytes()
    print(
        f"FIXTURE_CHANGE_PROOF existing={len(base)} changed={len(CHANGED_IDS)} "
        f"added={len(NEW_IDS) + len(WHI254_NEW_IDS)} "
        "allowed_existing_changes=one parent observation each "
        f"address_table_unchanged={str(table_same).lower()}"
    )
    print("NEW_FIXTURE_DIGESTS " + ",".join(f"{key}:{digests[key]}" for key in NEW_IDS))
    whi254_digests = {
        f["id"]: hashlib.sha256(canonical(f)).hexdigest()
        for f in current[len(base) + len(NEW_IDS):]
    }
    if whi254_digests != WHI254_NEW_DIGESTS:
        print(f"UNEXPECTED_WHI254_FIXTURE_CHANGE {whi254_digests}", file=sys.stderr)
        return 1
    print("WHI254_NEW_FIXTURE_DIGESTS " + ",".join(
        f"{key}:{whi254_digests[key]}" for key in WHI254_NEW_IDS
    ))
    changed_digests = {
        key: hashlib.sha256(canonical(current_by_id[key])).hexdigest()
        for key in CHANGED_IDS
    }
    if changed_digests != CHANGED_DIGESTS:
        print(f"UNEXPECTED_CHANGED_FIXTURE_CHANGE {changed_digests}", file=sys.stderr)
        return 1
    print("CHANGED_FIXTURE_DIGESTS " + ",".join(
        f"{key}:{changed_digests[key]}" for key in CHANGED_IDS
    ))
    if not table_same:
        return 1

    with tempfile.TemporaryDirectory(prefix="amino-whi180-preservation-") as temporary:
        old_repository = Path(temporary) / "base"
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT), str(old_repository)],
            check=True,
        )
        subprocess.run(["git", "checkout", "--quiet", BASE], cwd=old_repository, check=True)
        preserved_ids = (
            {fixture["id"] for fixture in base}
            - set(CHANGED_IDS)
            - set(WHI280_CHANGED_IDS)
        )
        old_outputs = snapshot_subprocess(old_repository, preserved_ids)
        current_outputs = snapshot_subprocess(ROOT, preserved_ids)
        old_whi280 = snapshot_subprocess(old_repository, set(WHI280_CHANGED_IDS))
        current_whi280 = snapshot_subprocess(ROOT, set(WHI280_CHANGED_IDS))

    output_changes = list(changes(old_outputs, current_outputs))
    grouped = Counter(path[-1] for path, _before, _after in output_changes)
    expected_ids = set(old_outputs)
    valid = set(current_outputs) == expected_ids and len(expected_ids) == 46 and not output_changes
    print(
        f"OUTPUT_PRESERVATION fixtures={len(current_outputs)} changed_keys={len(output_changes)} "
        f"by_key={dict(sorted(grouped.items()))} "
        f"sha256={hashlib.sha256(canonical(current_outputs)).hexdigest()}"
    )
    if not valid:
        for path, before, after in output_changes:
            print(f"UNEXPECTED_OUTPUT_CHANGE {path}: {before!r} -> {after!r}", file=sys.stderr)
        return 1
    whi280_changes = list(changes(old_whi280, current_whi280))
    whi280_marker_changes = [
        (path, before, after) for path, before, after in whi280_changes
        if path[-1:] == ("unconfirmed",) and before is None
    ]
    output_markers = {}
    for fixture_id, output in current_whi280.items():
        output_markers[fixture_id] = {
            (finding["area"], finding["title"]): finding["unconfirmed"]
            for finding in output["result"]["findings"]
            if "unconfirmed" in finding
        }
    whi280_valid = (
        len(whi280_changes) == 14
        and len(whi280_marker_changes) == 14
        and output_markers == WHI280_MARKERS
    )
    print(
        f"WHI280_OUTPUT_CHANGE_PROOF fixtures={len(current_whi280)} "
        f"changed_keys={len(whi280_changes)} "
        f"unconfirmed_only={str(len(whi280_marker_changes) == len(whi280_changes)).lower()} "
        f"sha256={hashlib.sha256(canonical(current_whi280)).hexdigest()}"
    )
    if not whi280_valid:
        for path, before, after in whi280_changes:
            print(f"UNEXPECTED_WHI280_OUTPUT_CHANGE {path}: {before!r} -> {after!r}", file=sys.stderr)
        print(f"UNEXPECTED_WHI280_MARKERS {output_markers!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
