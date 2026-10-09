#!/usr/bin/env python3
"""Prove the Python PSL gate rejects the former last-two-label fallback."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPTS = ROOT / "amino-deliverability-audit" / "skills" / "amino-deliverability-audit" / "scripts"
AUDIT = SCRIPTS / "audit.py"
RUNNER = HERE / "run_vectors.py"
ADAPTER = HERE / "adapters" / "skill.py"


def run(audit: Path, name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--name",
            name,
            "--",
            sys.executable,
            str(ADAPTER),
            str(audit),
        ],
        text=True,
        capture_output=True,
    )


def run_dmarc_boundary(audit: Path, name: str) -> subprocess.CompletedProcess[str]:
    probe = r'''import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
import audit

audit.confirm_txt = lambda qname, _prefix: {
    "_dmarc.nhs.uk": "v=DMARC1; p=reject",
}.get(qname.rstrip(".").lower())
actual = audit.discover_dmarc("trust.nhs.uk")
expected = (None, None, False)
if actual != expected:
    print(
        f"FAIL {sys.argv[2]} registrable-root-nhs-uk DMARC boundary: "
        f"expected {expected!r}, got {actual!r}"
    )
    raise SystemExit(1)
print(f"PASS {sys.argv[2]} registrable-root-nhs-uk DMARC boundary")
'''
    return subprocess.run(
        [sys.executable, "-c", probe, str(audit), name],
        text=True,
        capture_output=True,
    )


def main() -> int:
    healthy = run(AUDIT, "python-skill")
    if healthy.returncode or "VECTOR SUMMARY python-skill: 78 passed / 0 failed / 78 total" not in healthy.stdout:
        print("FAIL Python PSL canary healthy control", file=sys.stderr)
        print(healthy.stdout, file=sys.stderr)
        print(healthy.stderr, file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="amino-psl-python-canary-") as temporary:
        target = Path(temporary) / "scripts"
        shutil.copytree(SCRIPTS, target)
        mutated = target / "audit.py"
        source = mutated.read_text(encoding="utf-8")
        pattern = re.compile(r"def org_base\(host\):\n.*?\n\ndef count_spf_lookups", re.DOTALL)
        replacement = '''def org_base(host):
    """WHI-215 canary: restore the rejected last-two-label fallback."""
    if not isinstance(host, str) or host.startswith("."):
        return None
    labels = [label for label in host.rstrip(".").lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) > 1 else None


def count_spf_lookups'''
        mutated_source, count = pattern.subn(lambda _match: replacement, source)
        if count != 1:
            print(f"FAIL Python PSL canary mutation anchor: expected 1, got {count}", file=sys.stderr)
            return 1
        mutated.write_text(mutated_source, encoding="utf-8")
        result = run(mutated, "python-two-label-canary")
        diagnostic = (
            "FAIL python-two-label-canary #22: input='example.uk.com' "
            "expected='example.uk.com' actual='uk.com'"
        )
        if result.returncode == 0 or diagnostic not in result.stdout:
            print("FAIL Python PSL fallback mutation was not rejected by its named vector", file=sys.stderr)
            print(result.stdout, file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1

    healthy_boundary = run_dmarc_boundary(AUDIT, "python-skill")
    if healthy_boundary.returncode:
        print("FAIL Python DMARC boundary canary healthy control", file=sys.stderr)
        print(healthy_boundary.stdout, file=sys.stderr)
        print(healthy_boundary.stderr, file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="amino-psl-dmarc-canary-") as temporary:
        target = Path(temporary) / "scripts"
        shutil.copytree(SCRIPTS, target)
        mutated = target / "audit.py"
        source = mutated.read_text(encoding="utf-8")
        anchor = "    if not base or domain == base:\n"
        if source.count(anchor) != 1:
            print(
                "FAIL Python DMARC boundary canary mutation anchor: "
                f"expected 1, got {source.count(anchor)}",
                file=sys.stderr,
            )
            return 1
        mutated.write_text(source.replace(anchor, "    if not base:\n"), encoding="utf-8")
        boundary_result = run_dmarc_boundary(mutated, "python-dmarc-boundary-canary")
        boundary_diagnostic = (
            "FAIL python-dmarc-boundary-canary registrable-root-nhs-uk DMARC boundary: "
            "expected (None, None, False), got ('v=DMARC1; p=reject', 'nhs.uk', True)"
        )
        if boundary_result.returncode == 0 or boundary_diagnostic not in boundary_result.stdout:
            print("FAIL Python DMARC boundary mutation was not rejected", file=sys.stderr)
            print(boundary_result.stdout, file=sys.stderr)
            print(boundary_result.stderr, file=sys.stderr)
            return 1

    print("PASS Python PSL adoption mutation canaries: 2/2")
    print(diagnostic)
    print(boundary_diagnostic)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
