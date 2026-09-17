#!/usr/bin/env python3
"""Compare the reviewed base helper with the table-driven helper on every row."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "conformance"
SCRIPTS = (
    ROOT
    / "amino-deliverability-audit"
    / "skills"
    / "amino-deliverability-audit"
    / "scripts"
)
BASE = "34a8fcb35f40ef4340b67be8f95f05ca6a3839e5"
AUDIT_PATH = "amino-deliverability-audit/skills/amino-deliverability-audit/scripts/audit.py"
TABLE_PATH = "amino-deliverability-audit/skills/amino-deliverability-audit/scripts/address-contract.json"
EXPECTED_NEWLY_REFUSED = [
    "ipv6-zone-public-name",
    "ipv6-zone-public-numeric",
    "ipv6-zone-mapped-public",
    "list-public-ipv4-zone-ipv6",
]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def answers(row, rrtype):
    has_colon = rrtype == "AAAA"
    return [
        address for address in row["addresses"]
        if (":" in address) == has_colon
    ]


def allowed(module, row):
    module.dig = lambda _host, rrtype: answers(row, rrtype)
    return bool(module.host_public_ips("contract.invalid"))


def main():
    table = json.loads((HERE / "address-contract.json").read_text(encoding="utf-8"))
    old_source = subprocess.run(
        ["git", "show", f"{BASE}:{AUDIT_PATH}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    old_table = subprocess.run(
        ["git", "show", f"{BASE}:{TABLE_PATH}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    sys.path.insert(0, str(SCRIPTS))
    current = load_module("whi127_current_audit", SCRIPTS / "audit.py")
    with tempfile.TemporaryDirectory(prefix="amino-address-differential-") as temporary:
        old_path = Path(temporary) / "audit.py"
        old_path.write_text(old_source, encoding="utf-8")
        (Path(temporary) / "address-contract.json").write_text(
            old_table, encoding="utf-8",
        )
        old = load_module("whi127_base_audit", old_path)

        newly_refused = []
        newly_allowed = []
        for row in table["rows"]:
            old_result = allowed(old, row)
            new_result = allowed(current, row)
            if old_result and not new_result:
                classification = "newly refused, special range"
                newly_refused.append(row["id"])
            elif not old_result and new_result:
                classification = "newly allowed"
                newly_allowed.append(row["id"])
            else:
                classification = "unchanged"
            print(
                f"{row['id']}\told={'allow' if old_result else 'refuse'}\t"
                f"new={'allow' if new_result else 'refuse'}\t{classification}"
            )

    print(
        f"SUMMARY python={sys.version.split()[0]} rows={len(table['rows'])} "
        f"newly_refused={len(newly_refused)} newly_allowed={len(newly_allowed)}"
    )
    print("NEWLY_REFUSED " + ",".join(newly_refused))
    if newly_allowed:
        print("NEWLY_ALLOWED " + ",".join(newly_allowed), file=sys.stderr)
        return 1
    if newly_refused != EXPECTED_NEWLY_REFUSED:
        print(
            "expected newly refused rows " + ",".join(EXPECTED_NEWLY_REFUSED),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
