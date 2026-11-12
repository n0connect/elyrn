"""Checks that the CI fuzz step lists every Go fuzz target exactly once, and only real ones.

Usage:
  python3 -I scripts/check-fuzz-targets.py          check (make check-hardening, CI)
  python3 -I scripts/check-fuzz-targets.py --list   check, then print "<package> <target>" per
                                                    line in CI order (make fuzz reads this)

The list lives in one place: the "Fuzz targets (short run)" step of .github/workflows/ci.yml,
one `fuzz ./<package> <Target>` line per target, sorted by package then target. Every
`func FuzzX(` in a backend *_test.go file must appear there exactly once under its own package
directory, and every listed target must exist (the step once named a target that did not).
Exit 0 when the list is complete and sorted, 1 with one line per failure otherwise, 2 when the
workflow or the backend tree is missing.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
BACKEND = ROOT / "backend"
# A listed target: `fuzz ./internal/agent FuzzReceivedText` (the step's shell function)
LISTED = re.compile(r"^\s+fuzz (\./[\w./-]+) (Fuzz\w+)\s*$", re.MULTILINE)
# A defined target: `func FuzzReceivedText(f *testing.F)` at the start of a line
DEFINED = re.compile(r"^func (Fuzz\w+)\(", re.MULTILINE)
TEST_FILE_GLOB = "*_test.go"
LIST_FLAG = "--list"
USAGE = "usage: check-fuzz-targets.py [--list]"


def listed_targets():
    """[(package, target)] in the order the CI step runs them."""
    return LISTED.findall(CI_WORKFLOW.read_text(encoding="utf-8"))


def defined_targets():
    """{(package, target)} for every fuzz function in the backend's test files."""
    found = set()
    for path in BACKEND.rglob(TEST_FILE_GLOB):
        package = "./" + path.parent.relative_to(BACKEND).as_posix()
        for target in DEFINED.findall(path.read_text(encoding="utf-8")):
            found.add((package, target))
    return found


def failures(listed, defined):
    out = []
    seen = set()
    for entry in listed:
        if entry in seen:
            out.append("listed twice: " + " ".join(entry))
        seen.add(entry)
    out += ["listed but not defined: " + " ".join(e) for e in sorted(seen - defined)]
    out += ["defined but not listed: " + " ".join(e) for e in sorted(defined - seen)]
    if listed != sorted(listed):
        out.append("the list is not sorted by package, then target")
    return out


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != LIST_FLAG):
        print(USAGE, file=sys.stderr)
        return 2
    if not CI_WORKFLOW.is_file() or not BACKEND.is_dir():
        print("[ERROR] check-fuzz-targets: .github/workflows/ci.yml or backend/ is missing", file=sys.stderr)
        return 2
    listed = listed_targets()
    problems = failures(listed, defined_targets())
    if problems:
        for line in problems:
            print("[FAIL] fuzz targets: " + line, file=sys.stderr)
        return 1
    if len(sys.argv) == 2:
        for package, target in listed:
            print(package, target)
    else:
        print(f"[OK] check-fuzz-targets: CI lists all {len(listed)} Go fuzz targets exactly once")
    return 0


if __name__ == "__main__":
    sys.exit(main())
