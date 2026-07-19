#!/usr/bin/env python3
# csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
# This code is licensed under MIT license (see LICENSE for details)

"""Run clang-tidy on production sources and write build/lint.md.

Usage:
  scripts/lint.py                            # all configured checks
  scripts/lint.py readability-function-size  # one check (exact name or glob)
  scripts/lint.py -o PATH                    # custom output file
  scripts/lint.py -j N                       # parallel jobs (default: nproc)
  scripts/lint.py --build DIR                # custom build directory
  scripts/lint.py --tests                    # also lint *_test.c files
  scripts/lint.py --generated                # also lint *.gen.c files
  scripts/lint.py --no-denoise               # keep known false positives

The CHECK argument is forwarded verbatim as the glob in -checks='-*,CHECK'.
Use a trailing '*' for prefix matching, e.g. "readability-*".

Production code is defined as all C sources under src/ that are not test
files (*_test.c) and not generated files (*.gen.c). The third-party tree
(contrib/) is always excluded; --tests and --generated opt the respective
file groups back in.

Denoising: some valuable checks fire false positives on this project's own
facilities (the archetype is misc-include-cleaner on utils/ascii.h, an
ASCII-only <ctype.h> replacement). Findings that can be *proven* to be such
false positives are withheld from the main report into a separate section;
anything uncertain is kept, so a real defect is never dropped. --no-denoise
disables the pass entirely.
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


def _accepted_sources(build_dir: Path, accept) -> list[str]:
    """Return the compile_commands.json source files that pass the production
    filter, deduplicated and in database order.  These are passed to
    run-clang-tidy so only production sources are analyzed."""
    db_path = build_dir / "compile_commands.json"
    if not db_path.exists():
        sys.exit(f"error: {db_path} not found — run cmake first")
    db: list[dict] = json.loads(db_path.read_text(encoding="utf-8"))
    sources: list[str] = []
    seen: set[str] = set()
    for entry in db:
        fpath = entry["file"]
        if not accept(fpath) or fpath in seen:
            continue
        seen.add(fpath)
        sources.append(fpath)
    return sources


# ---------------------------------------------------------------------------
# Run clang-tidy
# ---------------------------------------------------------------------------

def _run(
    build_dir: Path, check_filter: str | None, jobs: int, sources: list[str]
) -> str:
    cmd = ["run-clang-tidy", "-p", str(build_dir), f"-j{jobs}"]
    if check_filter:
        cmd += [f"-checks=-*,{check_filter}"]
    # Pass the accepted production sources explicitly so clang-tidy analyzes
    # only those, rather than the whole src/ tree (whose test/generated results
    # would just be discarded during post-filtering, wasting the analysis and
    # inflating the reported elapsed time).
    cmd += sources
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=None,  # progress messages flow to the terminal unchanged
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,  # returncode is inspected explicitly below
        )
    except FileNotFoundError:
        sys.exit("error: run-clang-tidy not found — install the llvm tools package")
    # A non-zero status means the driver (or a clang-tidy invocation) errored:
    # a malformed compile command, an internal crash, a rejected -checks glob.
    # The captured stdout is then empty or partial, so treating it as "no
    # warnings" would report a broken run as a clean tree. Fail loudly instead.
    if proc.returncode != 0:
        sys.exit(
            f"error: run-clang-tidy exited with status {proc.returncode}; "
            "lint results are unreliable (a tool failure is not a clean run)")
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
# Denoising
#
# Some checks are valuable in general but fire false positives on this
# project's own facilities. The archetype is misc-include-cleaner and
# utils/ascii.h: ascii.h defines the character-classification family
# (isdigit, isalnum, isprint, tolower, ...) as ASCII-only macros that
# deliberately replace <ctype.h> — the two are mutually exclusive, ascii.h
# #errors if ctype.h's macros are already defined. include-cleaner maps those
# names to <ctype.h> unconditionally and reports "no header providing isdigit",
# a demand that is impossible to satisfy here.
#
# The denoiser withholds only findings it can PROVE are such false positives;
# it must never drop a finding that could be a real defect. Each rule is
# therefore anchored to concrete evidence in the source — here: the flagged
# name is one ascii.h actually defines AND the flagged file itself includes
# ascii.h. A <ctype.h>-unrelated missing include (pid_t, char32_t, openlog,
# ...) is left untouched. Suppressed findings are still reported in their own
# section, and --no-denoise disables the pass, so nothing is silently hidden.
# ---------------------------------------------------------------------------

ASCII_HEADER = "utils/ascii.h"  # spelling used in #include directives

# Include roots under which the "utils/ascii.h" spelling resolves on disk,
# mirroring the build's -I paths. In csnippets itself the header lives under
# src/; the downstream projects vendor csnippets under contrib/csnippets/, so
# the same include spelling resolves there instead. Searched in order; the
# first hit wins (only one root exists in any given tree). Without this the
# denoiser silently no-ops in the vendored trees and every ascii.h finding
# leaks into the report as if it were a real defect.
_HEADER_INCLUDE_ROOTS = ("src", "contrib/csnippets")

# misc-include-cleaner phrasing for a used-but-not-directly-included symbol.
_INCLUDE_CLEANER_MISSING_RE = re.compile(
    r'^no header providing "(?P<sym>[^"]+)" is directly included$'
)

# An #include whose target basename is ascii.h — e.g. #include "utils/ascii.h",
# the bare "ascii.h" spelling used from within utils/, the vendored
# "csnippets/utils/ascii.h", or any <...> form. Anchoring on the basename keeps
# the rule correct regardless of the include-path prefix a project spells it
# with, while the leading "/"-or-start requirement rejects unrelated names like
# "myascii.h".
_ASCII_INCLUDE_RE = re.compile(
    r'^[ \t]*#[ \t]*include[ \t]*[<"](?:[^">]*/)?ascii\.h[">]',
    re.MULTILINE,
)


def _ascii_provided_names(root: Path) -> set[str]:
    """Names that utils/ascii.h provides (macros and inline functions).

    Parsed from the header itself so the set stays correct as ascii.h evolves.
    The header is looked up under each known include root (src/ for csnippets,
    contrib/csnippets/ for the downstream projects that vendor it). Returns an
    empty set if it cannot be read under any root — the ascii.h rule then simply
    never fires (fail safe: keep every finding).
    """
    text: str | None = None
    for inc_root in _HEADER_INCLUDE_ROOTS:
        try:
            text = (root / inc_root / ASCII_HEADER).read_text(encoding="utf-8")
        except OSError:
            continue
        break
    if text is None:
        return set()
    names: set[str] = set()
    names.update(re.findall(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)", text,
                            re.MULTILINE))
    names.update(re.findall(r"\bstatic[ \t]+inline\b[^;{]*?\b([A-Za-z_]\w*)[ \t]*\(",
                            text, re.DOTALL))
    return names


def _denoise(
    warnings: list[dict], root: Path
) -> tuple[list[dict], list[dict]]:
    """Split warnings into (kept, suppressed).

    A warning is suppressed only when a rule can prove it is a false positive
    caused by one of this project's own facilities; suppressed warnings carry a
    human-readable 'reason'. Everything else — including anything uncertain —
    is kept.
    """
    ascii_names = _ascii_provided_names(root)
    include_cache: dict[str, bool] = {}

    def file_includes_ascii(relpath: str) -> bool:
        if relpath not in include_cache:
            try:
                src = (root / relpath).read_text(encoding="utf-8")
            except OSError:
                include_cache[relpath] = False
            else:
                include_cache[relpath] = bool(_ASCII_INCLUDE_RE.search(src))
        return include_cache[relpath]

    def noise_reason(w: dict) -> str | None:
        # Rule: misc-include-cleaner "no header providing <sym>" where <sym> is
        # defined by ascii.h and the flagged file includes ascii.h.
        if not ascii_names or w["check"] != "misc-include-cleaner":
            return None
        m = _INCLUDE_CLEANER_MISSING_RE.match(w["msg"])
        if m is None:
            return None
        sym = m.group("sym")
        if sym not in ascii_names or not file_includes_ascii(w["file"]):
            return None
        return (
            f"`{ASCII_HEADER}` provides `{sym}` "
            "(ASCII-only <ctype.h> replacement)"
        )

    kept: list[dict] = []
    suppressed: list[dict] = []
    for w in warnings:
        reason = noise_reason(w)
        if reason is None:
            kept.append(w)
        else:
            suppressed.append({**w, "reason": reason})
    return kept, suppressed


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def _excluded_labels(include_tests: bool, include_generated: bool) -> list[str]:
    """Human-readable list of the file groups the source filter excludes."""
    labels = ["`contrib/`"]
    if not include_tests:
        labels.append("`*_test.c`")
    if not include_generated:
        labels.append("`*.gen.c`")
    return labels


def _suppressed_section(suppressed: list[dict]) -> list[str]:
    """Render the 'Suppressed (known noise)' table, or nothing if empty."""
    if not suppressed:
        return []
    out = [
        "## Suppressed (known noise)",
        "",
        f"{len(suppressed)} finding(s) withheld as provable false positives "
        "from this project's own facilities (e.g. `utils/ascii.h`). These are "
        "not real defects; re-run with `--no-denoise` to include them above.",
        "",
        "| Check | File | Line | Message | Reason |",
        "|---|---|---:|---|---|",
    ]
    for w in sorted(suppressed, key=lambda w: (w["check"], w["file"], w["line"])):
        msg = w["msg"].replace("|", "\\|").replace("`", "\\`")
        reason = w["reason"].replace("|", "\\|")
        out.append(
            f"| `{w['check']}` | `{w['file']}` | {w['line']} | {msg} | {reason} |"
        )
    out.append("")
    return out


def _report(
    warnings: list[dict], suppressed: list[dict], check_filter: str | None,
    elapsed: float, excluded: list[str],
) -> str:
    title = f"`{check_filter}`" if check_filter else "All Checks"
    total = len(warnings)

    meta = (
        f"**Date:** {datetime.date.today().isoformat()} &ensp;"
        f" **Elapsed:** {elapsed:.1f} s &ensp;"
        f" **Warnings:** {total}"
    )
    if suppressed:
        meta += f" &ensp; **Suppressed:** {len(suppressed)}"

    out: list[str] = []
    out += [
        f"# Clang-Tidy Lint Report — {title}",
        "",
        meta,
        "",
        f"> Source filter: excludes {', '.join(excluded)}",
        "",
    ]

    if not warnings:
        out.append(
            "_No actionable warnings after denoising._" if suppressed
            else "_No warnings found._"
        )
        out.append("")
        out += _suppressed_section(suppressed)
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

    out += _suppressed_section(suppressed)

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """Parse arguments, run clang-tidy, and write the Markdown report."""
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
    ap.add_argument(
        "--no-denoise",
        action="store_true",
        help="keep known false positives (e.g. the utils/ascii.h "
        "include-cleaner noise) instead of withholding them",
    )
    args = ap.parse_args()

    build_dir = Path(args.build)
    out_path = Path(args.output)
    check_label = args.check or "all checks"

    accept = _make_filter(args.tests, args.generated)
    name_map = _build_name_map(build_dir, accept)
    sources = _accepted_sources(build_dir, accept)
    if not sources:
        # No accepted sources: passing zero positional paths would make
        # run-clang-tidy analyze the entire database, so stop here instead.
        sys.exit("error: no sources to lint after applying the source filter")

    print(f"Linting [{check_label}] ...", file=sys.stderr, flush=True)
    t0 = time.monotonic()
    raw = _run(build_dir, args.check, args.jobs, sources)
    elapsed = time.monotonic() - t0

    warnings = _parse(raw, name_map, accept)
    if args.no_denoise:
        kept, suppressed = warnings, []
    else:
        kept, suppressed = _denoise(warnings, ROOT)

    print(
        f"{len(kept)} warning(s)"
        f"{f', {len(suppressed)} suppressed' if suppressed else ''}"
        f" in {elapsed:.1f} s → {out_path}",
        file=sys.stderr,
    )

    md = _report(
        kept, suppressed, args.check, elapsed,
        _excluded_labels(args.tests, args.generated),
    )
    out_path.write_text(md, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
