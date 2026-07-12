#!/usr/bin/env python3

"""Run clang-tidy on production sources and write build/lint.md.

Usage:
  scripts/lint.py                            # all configured checks
  scripts/lint.py readability-function-size  # one check (exact name or glob)
  scripts/lint.py -o PATH                    # custom output file
  scripts/lint.py -j N                       # parallel jobs (default: nproc)
  scripts/lint.py --build DIR                # custom build directory
  scripts/lint.py --tests                    # also lint *_test.c files
  scripts/lint.py --generated                # also lint *.gen.c files

The CHECK argument is forwarded verbatim as the glob in -checks='-*,CHECK'.
Use a trailing '*' for prefix matching, e.g. "readability-*".

Production code is defined as all C sources under src/ that are not test
files (*_test.c) and not generated files (*.gen.c). The third-party tree
(contrib/) is always excluded; --tests and --generated opt the respective
file groups back in.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "lint.md"

# ---------------------------------------------------------------------------
# Production-source filter
# ---------------------------------------------------------------------------

_EXCL_CONTRIB = re.compile(r"(?:^|/)contrib/")  # third-party tree
_EXCL_TEST = re.compile(r"_test\.c$")            # unit-test files
_EXCL_GEN = re.compile(r"\.gen\.c$")             # generated files


def _make_filter(include_tests: bool, include_generated: bool):
    """Return a predicate that accepts source paths to be linted.

    contrib/ is always excluded; test and generated files are excluded
    unless opted back in.
    """
    excl = [_EXCL_CONTRIB]
    if not include_tests:
        excl.append(_EXCL_TEST)
    if not include_generated:
        excl.append(_EXCL_GEN)
    return lambda path: not any(p.search(path) for p in excl)


# ---------------------------------------------------------------------------
# Build a basename → canonical-relative-path lookup from compile_commands.json
# so that prefix-mapped paths like "dispatch.c" are shown as "src/mux/dispatch.c".
# ---------------------------------------------------------------------------

def _build_name_map(build_dir: Path, accept) -> dict[str, str]:
    db_path = build_dir / "compile_commands.json"
    if not db_path.exists():
        sys.exit(f"error: {db_path} not found — run cmake first")
    db: list[dict] = json.loads(db_path.read_text(encoding="utf-8"))
    mapping: dict[str, str] = {}
    ambiguous: set[str] = set()
    for entry in db:
        fpath = entry["file"]
        if not accept(fpath):
            continue
        pobj = Path(fpath)
        try:
            rel = str(pobj.relative_to(ROOT))
        except ValueError:
            rel = str(pobj)
        name = pobj.name
        if name in mapping and mapping[name] != rel:
            ambiguous.add(name)
        mapping[name] = rel  # basename → "src/mux/dispatch.c"
    # two sources sharing a basename can't be told apart from a basename
    # alone — drop them so lookups fall back to the raw (unmapped) path
    # instead of silently guessing the wrong file.
    for name in ambiguous:
        del mapping[name]
    return mapping


# ---------------------------------------------------------------------------
# Run clang-tidy
# ---------------------------------------------------------------------------

def _run(build_dir: Path, check_filter: str | None, jobs: int) -> str:
    cmd = ["run-clang-tidy", "-p", str(build_dir), f"-j{jobs}"]
    if check_filter:
        cmd += [f"-checks=-*,{check_filter}"]
    # Restrict to src/ files; post-filter removes tests and generated files.
    cmd.append("src/")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=None,  # progress messages flow to the terminal unchanged
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        sys.exit("error: run-clang-tidy not found — install the llvm tools package")
    return proc.stdout


# ---------------------------------------------------------------------------
# Parse clang-tidy output into structured warnings
# ---------------------------------------------------------------------------

# FILE:LINE:COL: warning: MESSAGE [check-name]
_WARN_RE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+warning:\s+"
    r"(?P<msg>.+?)\s+\[(?P<check>[^\]]+)\]\s*$"
)


def _parse(raw: str, name_map: dict[str, str], accept) -> list[dict]:
    result = []
    seen: set[tuple[str, int, str, str]] = set()
    for text in raw.splitlines():
        m = _WARN_RE.match(text.rstrip())
        if not m:
            continue
        fpath = m.group("file")
        if not accept(fpath):
            continue

        # Resolve the (possibly prefix-mapped) path to a canonical relative path.
        pobj = Path(fpath)
        if pobj.is_absolute():
            try:
                relpath = str(pobj.relative_to(ROOT))
            except ValueError:
                relpath = str(pobj)
        else:
            # e.g. "dispatch.c" or "mux/dispatch.c" — look up by basename
            relpath = name_map.get(pobj.name, fpath)

        line = int(m.group("line"))
        check = m.group("check")
        msg = m.group("msg")
        # run-clang-tidy repeats a header's warnings once per translation
        # unit that includes it; keep only the first occurrence.
        key = (relpath, line, check, msg)
        if key in seen:
            continue
        seen.add(key)

        result.append(
            {
                "file": relpath,
                "line": line,
                "msg": msg,
                "check": check,
            }
        )
    return result


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def _report(
    warnings: list[dict], check_filter: str | None, elapsed: float,
    include_tests: bool, include_generated: bool,
) -> str:
    title = f"`{check_filter}`" if check_filter else "All Checks"
    total = len(warnings)

    excluded = ["`contrib/`"]
    if not include_tests:
        excluded.append("`*_test.c`")
    if not include_generated:
        excluded.append("`*.gen.c`")

    out: list[str] = []
    out += [
        f"# Clang-Tidy Lint Report — {title}",
        "",
        f"**Date:** {datetime.date.today().isoformat()} &ensp;"
        f" **Elapsed:** {elapsed:.1f} s &ensp;"
        f" **Warnings:** {total}",
        "",
        f"> Source filter: excludes {', '.join(excluded)}",
        "",
    ]

    if not warnings:
        out.append("_No warnings found._")
        return "\n".join(out)

    # Organise: check → file → [(line, msg)]
    by_check: dict[str, dict[str, list[tuple[int, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for w in warnings:
        by_check[w["check"]][w["file"]].append((w["line"], w["msg"]))

    check_totals: dict[str, int] = {
        c: sum(len(ws) for ws in files.values())
        for c, files in by_check.items()
    }
    single_check = len(by_check) == 1

    # --- Summary ---
    out += ["## Summary", ""]
    if single_check:
        files_map = next(iter(by_check.values()))
        out += ["| File | Warnings |", "|---|---:|"]
        for f in sorted(files_map, key=lambda k: (-len(files_map[k]), k)):
            out.append(f"| `{f}` | {len(files_map[f])} |")
    else:
        out += ["| Check | Warnings |", "|---|---:|"]
        for c in sorted(check_totals, key=lambda k: -check_totals[k]):
            out.append(f"| `{c}` | {check_totals[c]} |")
    out.append("")

    # --- Findings ---
    out += ["## Findings", ""]
    for check in sorted(by_check):
        if not single_check:
            out += [f"### `{check}`", ""]
        for fpath in sorted(by_check[check]):
            entries = sorted(by_check[check][fpath])
            n = len(entries)
            noun = "warning" if n == 1 else "warnings"
            label = f"**`{fpath}`** — {n} {noun}"
            out.append(f"{'###' if single_check else '####'} {label}")
            out.append("")
            out += ["| Line | Message |", "|---:|---|"]
            for line_no, msg in entries:
                safe = msg.replace("|", "\\|").replace("`", "\\`")
                out.append(f"| {line_no} | {safe} |")
            out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "check",
        nargs="?",
        metavar="CHECK",
        help="check name or glob, e.g. readability-function-size or readability-*",
    )
    ap.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=str(DEFAULT_OUTPUT),
        help="output path (default: %(default)s)",
    )
    ap.add_argument(
        "-j", "--jobs",
        type=int,
        default=os.cpu_count() or 4,
        metavar="N",
        help="parallel clang-tidy jobs (default: %(default)s)",
    )
    ap.add_argument(
        "--build",
        metavar="DIR",
        default=str(DEFAULT_BUILD_DIR),
        help="build directory with compile_commands.json (default: %(default)s)",
    )
    ap.add_argument(
        "--tests",
        action="store_true",
        help="also lint test files (*_test.c)",
    )
    ap.add_argument(
        "--generated",
        action="store_true",
        help="also lint generated files (*.gen.c)",
    )
    args = ap.parse_args()

    build_dir = Path(args.build)
    out_path = Path(args.output)
    check_label = args.check or "all checks"

    accept = _make_filter(args.tests, args.generated)
    name_map = _build_name_map(build_dir, accept)

    print(f"Linting [{check_label}] ...", file=sys.stderr, flush=True)
    t0 = time.monotonic()
    raw = _run(build_dir, args.check, args.jobs)
    elapsed = time.monotonic() - t0

    warnings = _parse(raw, name_map, accept)
    print(
        f"{len(warnings)} warning(s) in {elapsed:.1f} s → {out_path}",
        file=sys.stderr,
    )

    md = _report(warnings, args.check, elapsed, args.tests, args.generated)
    out_path.write_text(md, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
