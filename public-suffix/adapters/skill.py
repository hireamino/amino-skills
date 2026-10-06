#!/usr/bin/env python3
"""Official-vector adapter for amino-skills' current org_base()."""

import importlib.util
import json
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: skill.py /path/to/audit.py")
    source = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location("measured_audit", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    results = []
    for domain in json.load(sys.stdin):
        try:
            results.append(module.org_base(domain))
        except Exception as exc:  # the runner records the current implementation, including errors
            results.append({"error": type(exc).__name__})
    json.dump(results, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
