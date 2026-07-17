#!/usr/bin/env python3
# csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
# This code is licensed under MIT license (see LICENSE for details)

"""Build gcov coverage data and print a Markdown coverage report.

This script uses only the Python standard library and external tools that are
normally present on a development system: cmake, ctest, and gcov.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_COVERAGE_BUILD_DIR = DEFAULT_BUILD_DIR / "gcov"
DEFAULT_MARKDOWN_OUTPUT = DEFAULT_BUILD_DIR / "gcov.md"
DEFAULT_SOURCE_DIRS = ("src",)
DEFAULT_EXCLUDE_SOURCE_SUFFIXES = ("_test.c",)
CACHE_LINE_RE = re.compile(r"^([A-Za-z0-9_]+):[^=]+=(.*)$")
HIT_COUNT_RE = re.compile(r"^([0-9]+)")


@dataclass
class FileCoverage:
    """Per-file line-coverage accumulator gathered from gcov output."""

    executable_lines: Set[int] = field(default_factory=set)
    executed_lines: Set[int] = field(default_factory=set)
    line_hits: Dict[int, int] = field(default_factory=dict)

    @property
    def covered(self) -> int:
        """Number of executable lines that were executed at least once."""
        return len(self.executed_lines)

    @property
    def total(self) -> int:
        """Number of executable lines in the file."""
        return len(self.executable_lines)

    @property
    def percent(self) -> float:
        """Line-coverage percentage (0.0 when there are no executable lines)."""
        if self.total == 0:
            return 0.0
        return 100.0 * float(self.covered) / float(self.total)


def log(message: str) -> None:
    """Print *message* to stderr."""
    print(message, file=sys.stderr)


def quote_command(command: Sequence[str]) -> str:
    """Return *command* as a shell-quoted single string for logging."""
    return " ".join(shlex.quote(part) for part in command)


def run_command(
        command: Sequence[str],
        *,
        cwd: Optional[Path] = None,
        check: bool = True,
        capture_output: bool = False,
        log_command: bool = True,
) -> subprocess.CompletedProcess:
    """Run *command*, optionally capturing output; exit on failure when *check*."""
    if log_command:
        log(f"+ {quote_command(command)}")
    proc = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        text=True,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        check=False,  # returncode is handled explicitly below via *check*
    )
    if check and proc.returncode != 0:
        if capture_output and proc.stdout:
            log(proc.stdout.rstrip())
        if capture_output and proc.stderr:
            log(proc.stderr.rstrip())
        raise SystemExit(proc.returncode)
    return proc


def resolve_path(base: Path, value: str) -> Path:
    """Resolve *value* against *base* when relative and canonicalize it."""
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def is_relative_to(path: Path, other: Path) -> bool:
    """Return whether *path* is lexically located under *other*."""
    try:
        path.relative_to(other)
        return True
    except ValueError:
        return False


def normalize_relative_dir(value: str, option_name: str) -> Path:
    """Normalize *value* to a repo-relative dir, rejecting absolute/escaping paths."""
    path = Path(os.path.normpath(value))
    if path.is_absolute():
        raise SystemExit(
            f"{option_name} must be relative to the repository root: {value}"
        )
    if any(part == ".." for part in path.parts):
        raise SystemExit(
            f"{option_name} must stay within the repository root: {value}"
        )
    return path


def parse_source_dirs(values: Optional[Sequence[str]]) -> List[Path]:
    """Normalize and de-duplicate the --source-dir values (default: src)."""
    source_dirs: List[Path] = []
    seen: Set[str] = set()
    for value in values or DEFAULT_SOURCE_DIRS:
        source_dir = normalize_relative_dir(value, "--source-dir")
        key = source_dir.as_posix()
        if key in seen:
            continue
        seen.add(key)
        source_dirs.append(source_dir)
    return source_dirs


def parse_exclude_source_suffixes(values: Optional[Sequence[str]]) -> Tuple[str, ...]:
    """De-duplicate the excluded basename suffixes (default: _test.c)."""
    if not values:
        return DEFAULT_EXCLUDE_SOURCE_SUFFIXES
    return tuple(dict.fromkeys(values))


def should_track_source(
        rel_path: Path,
        source_dirs: Sequence[Path],
        exclude_source_suffixes: Sequence[str],
) -> bool:
    """Return whether *rel_path* is a tracked ``.c`` source under *source_dirs*."""
    if rel_path.suffix != ".c":
        return False
    if any(rel_path.name.endswith(suffix) for suffix in exclude_source_suffixes):
        return False
    return any(is_relative_to(rel_path, source_dir) for source_dir in source_dirs)


def parse_cmake_cache(cache_path: Path) -> Dict[str, str]:
    """Parse a CMakeCache.txt file into a ``{name: value}`` dict."""
    cache: Dict[str, str] = {}
    if not cache_path.exists():
        return cache
    with cache_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            match = CACHE_LINE_RE.match(line)
            if match is None:
                continue
            cache[match.group(1)] = match.group(2)
    return cache


def ensure_tool(name: str) -> str:
    """Return the path to tool *name*, exiting if it is not on PATH."""
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"required tool not found: {name}")
    return path


def ensure_project_root(root: Path) -> None:
    """Exit unless *root* looks like the project root (has CMakeLists.txt)."""
    if not (root / "CMakeLists.txt").exists():
        raise SystemExit(
            f"working directory does not look like the project root: {root}"
        )


def build_configure_command(
        cmake: str,
        base_cache: Dict[str, str],
        coverage_build_dir: Path,
        build_type: str,
) -> List[str]:
    """Build the cmake configure command line for the coverage build."""
    command = [
        cmake,
        "-S",
        str(ROOT),
        "-B",
        str(coverage_build_dir),
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DBUILD_TESTING=ON",
        "-DENABLE_SANITIZERS=OFF",
        # Config-agnostic so every --build-type is instrumented: CMAKE_C_FLAGS
        # applies to all configurations, whereas CMAKE_C_FLAGS_<CONFIG> would
        # carry --coverage only for that one configuration (Debug), leaving any
        # other build type with no .gcno files.
        "-DCMAKE_C_FLAGS=-O0 -g --coverage",
        "-DCMAKE_EXE_LINKER_FLAGS=--coverage",
        "-DCMAKE_SHARED_LINKER_FLAGS=--coverage",
        "-DCMAKE_MODULE_LINKER_FLAGS=--coverage",
        f"-DCMAKE_BUILD_TYPE={build_type}",
    ]
    compiler = base_cache.get("CMAKE_C_COMPILER")
    if compiler:
        command.append(f"-DCMAKE_C_COMPILER={compiler}")
    return command


def remove_stale_gcda_files(build_dir: Path) -> int:
    """Delete all ``.gcda`` files under *build_dir*; return how many were removed."""
    removed = 0
    for path in build_dir.rglob("*.gcda"):
        path.unlink()
        removed += 1
    return removed


def iter_expected_sources(
        source_dirs: Sequence[Path], exclude_source_suffixes: Sequence[str]
) -> List[str]:
    """Return the sorted, de-duplicated tracked sources under *source_dirs*."""
    sources: List[str] = []
    seen: Set[str] = set()
    for source_dir in source_dirs:
        root_path = ROOT / source_dir
        if root_path.is_file():
            rel_path = root_path.relative_to(ROOT)
            if should_track_source(rel_path, source_dirs, exclude_source_suffixes):
                key = rel_path.as_posix()
                if key not in seen:
                    seen.add(key)
                    sources.append(key)
            continue
        if not root_path.exists():
            log(
                f"warning: source directory not found: {source_dir.as_posix()}")
            continue
        for path in sorted(root_path.rglob("*.c")):
            rel_path = path.relative_to(ROOT)
            if not should_track_source(rel_path, source_dirs, exclude_source_suffixes):
                continue
            key = rel_path.as_posix()
            if key in seen:
                continue
            seen.add(key)
            sources.append(key)
    return sources


def iter_object_files(build_dir: Path) -> List[Path]:
    """Return the sorted instrumented object files (those with a ``.gcno``)."""
    objects: List[Path] = []
    for path in sorted(build_dir.rglob("*.o")):
        if "CMakeFiles" not in path.parts:
            continue
        if not path.with_suffix(".gcno").exists():
            continue
        objects.append(path)
    return objects


def normalize_source_path(
        source_text: str,
        source_dirs: Sequence[Path],
        exclude_source_suffixes: Sequence[str],
) -> Optional[str]:
    """Return *source_text* as a tracked repo-relative path, or None if untracked."""
    source_path = Path(source_text)
    if not source_path.is_absolute():
        source_path = (ROOT / source_path).resolve()
    else:
        source_path = source_path.resolve()
    try:
        rel_path = source_path.relative_to(ROOT)
    except ValueError:
        return None
    if not should_track_source(rel_path, source_dirs, exclude_source_suffixes):
        return None
    return rel_path.as_posix()


def parse_gcov_file(
        path: Path,
        coverage: Dict[str, FileCoverage],
        source_dirs: Sequence[Path],
        exclude_source_suffixes: Sequence[str],
) -> None:
    """Parse one gcov ``.gcov`` file, accumulating line data into *coverage*."""
    source_rel: Optional[str] = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            parts = raw_line.rstrip("\n").split(":", 2)
            if len(parts) != 3:
                continue
            count_field, line_field, payload = parts
            try:
                line_number = int(line_field.strip())
            except ValueError:
                continue
            if line_number == 0 and payload.startswith("Source:"):
                source_rel = normalize_source_path(
                    payload[len("Source:"):].strip(),
                    source_dirs,
                    exclude_source_suffixes,
                )
                continue
            if source_rel is None or line_number <= 0:
                continue
            count_token = count_field.strip()
            if count_token == "-":
                continue
            file_coverage = coverage.setdefault(source_rel, FileCoverage())
            file_coverage.executable_lines.add(line_number)
            if count_token in {"#####", "====="}:
                continue
            match = HIT_COUNT_RE.match(count_token)
            if match is None:
                continue
            hit_count = int(match.group(1))
            if hit_count > 0:
                file_coverage.line_hits[line_number] = (
                    file_coverage.line_hits.get(line_number, 0) + hit_count
                )
                file_coverage.executed_lines.add(line_number)


def clear_line_coverage_dir(output_dir: Path) -> None:
    """Remove and recreate *output_dir* so it starts empty."""
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def write_line_coverage_files(
        output_dir: Path,
        coverage: Dict[str, FileCoverage],
        rows: Sequence[Tuple[str, int, int, float]],
) -> Set[str]:
    """Write a per-line ``.gcov`` file for each source that has coverage data
    and still exists on disk; return the set of source paths actually written
    so the report only links files that exist."""
    clear_line_coverage_dir(output_dir)
    percent_by_source = {path: percent for path,
                         _covered, _total, percent in rows}
    written: Set[str] = set()
    for source_rel, file_coverage in sorted(coverage.items()):
        source_path = ROOT / source_rel
        if not source_path.exists():
            continue
        output_path = output_dir / (source_rel + ".gcov")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        percent = percent_by_source.get(source_rel, 0.0)
        with source_path.open("r", encoding="utf-8", errors="replace") as src:
            source_lines = src.read().splitlines()
        with output_path.open("w", encoding="utf-8") as out:
            out.write(f"        -:    0:Source:{source_rel}\n")
            out.write("        -:    0:Generator:gcov.py\n")
            out.write(
                "        -:    0:Lines executed:"
                f"{percent:.2f}% of {file_coverage.total}\n"
            )
            for line_number, source_line in enumerate(source_lines, start=1):
                if line_number not in file_coverage.executable_lines:
                    count_token = "-"
                else:
                    hit_count = file_coverage.line_hits.get(line_number, 0)
                    count_token = str(hit_count) if hit_count > 0 else "#####"
                out.write(f"{count_token:>9}:{line_number:5d}:{source_line}\n")
        written.add(source_rel)
    return written


def populate_gcov_work_dir(work_dir: Path) -> None:
    """Mirror the repo root into *work_dir* as symlinks for gcov to run under."""
    for entry in ROOT.iterdir():
        link_path = work_dir / entry.name
        try:
            link_path.symlink_to(entry, target_is_directory=entry.is_dir())
        except FileExistsError:
            continue


def collect_coverage(
        gcov: str,
        build_dir: Path,
        object_files: Sequence[Path],
        source_dirs: Sequence[Path],
        exclude_source_suffixes: Sequence[str],
) -> Dict[str, FileCoverage]:
    """Run gcov on every object file and aggregate per-source coverage."""
    coverage: Dict[str, FileCoverage] = {}
    with tempfile.TemporaryDirectory(prefix="gcov-py-") as temp_root:
        temp_root_path = Path(temp_root)
        for index, object_file in enumerate(object_files, start=1):
            work_dir = temp_root_path / f"obj-{index:04d}"
            work_dir.mkdir()
            populate_gcov_work_dir(work_dir)
            proc = run_command(
                [gcov, "-b", "-c", "-p", "-m", str(object_file)],
                cwd=work_dir,
                check=False,
                capture_output=True,
                log_command=False,
            )
            gcov_files = sorted(work_dir.glob("*.gcov"))
            if proc.returncode != 0 and not gcov_files:
                log(
                    "warning: gcov failed for "
                    f"{object_file.relative_to(build_dir).as_posix()}"
                )
                if proc.stderr:
                    log(proc.stderr.rstrip())
                continue
            for gcov_file in gcov_files:
                parse_gcov_file(
                    gcov_file,
                    coverage,
                    source_dirs,
                    exclude_source_suffixes,
                )
    return coverage


def summarize_rows(
        expected_sources: Iterable[str], coverage: Dict[str, FileCoverage]
) -> List[Tuple[str, int, int, float]]:
    """Return ``(source, covered, total, percent)`` rows for every expected source."""
    rows: List[Tuple[str, int, int, float]] = []
    for source in expected_sources:
        file_coverage = coverage.get(source, FileCoverage())
        rows.append(
            (source, file_coverage.covered,
             file_coverage.total, file_coverage.percent)
        )
    return rows


def format_percent(covered: int, total: int) -> str:
    """Format a coverage percentage as ``NN.NN%`` (``0.00%`` when *total* is 0)."""
    if total == 0:
        return "0.00%"
    return f"{100.0 * float(covered) / float(total):.2f}%"


def markdown_table(title: str, rows: Sequence[Tuple[str, int, int]]) -> List[str]:
    """Render *rows* as a titled Markdown coverage table (list of lines)."""
    lines = [title, "", "| Scope | Covered | Total | Line % |",
             "| --- | ---: | ---: | ---: |"]
    for label, covered, total in rows:
        lines.append(
            f"| {label} | {covered} | {total} | "
            f"{format_percent(covered, total)} |"
        )
    return lines


def relative_markdown_path(base_dir: Path, target: Path) -> str:
    """Return *target* relative to *base_dir* using forward slashes for Markdown."""
    return os.path.relpath(target, start=base_dir).replace(os.sep, "/")


def label_source_dir(source_dir: Path) -> str:
    """Return the summary label for *source_dir* (``root`` for the repo root)."""
    label = source_dir.as_posix()
    return "root" if label == "." else label


def classify_summary_scope(source_rel: str, source_dirs: Sequence[Path]) -> str:
    """Return the summary bucket a source belongs to (its top-level scope)."""
    rel_path = Path(source_rel)
    for source_dir in source_dirs:
        if not is_relative_to(rel_path, source_dir):
            continue
        remainder = rel_path.relative_to(source_dir)
        if len(remainder.parts) <= 1:
            return label_source_dir(source_dir)
        if source_dir.as_posix() == ".":
            return remainder.parts[0]
        return (source_dir / remainder.parts[0]).as_posix()
    parent = rel_path.parent.as_posix()
    return parent if parent != "." else "root"


def build_summary_rows(
        rows: Sequence[Tuple[str, int, int, float]], source_dirs: Sequence[Path]
) -> List[Tuple[str, int, int]]:
    """Aggregate per-file rows into per-scope summary rows plus an overall total."""
    summary_map: Dict[str, List[int]] = {}
    all_covered = 0
    all_total = 0
    for path, covered, total, _percent in rows:
        all_covered += covered
        all_total += total
        label = classify_summary_scope(path, source_dirs)
        bucket = summary_map.setdefault(label, [0, 0])
        bucket[0] += covered
        bucket[1] += total
    summary_rows = [
        (label, counts[0], counts[1]) for label, counts in summary_map.items()
    ]
    summary_rows.append(("overall", all_covered, all_total))
    return summary_rows


def render_markdown_report(
        rows: Sequence[Tuple[str, int, int, float]],
        *,
        output_path: Path,
        line_output_dir: Path,
        source_dirs: Sequence[Path],
        line_files: Set[str],
) -> str:
    """Render the full Markdown coverage report (summary + per-file table)."""
    summary_rows = build_summary_rows(rows, source_dirs)

    sorted_rows = sorted(rows, key=lambda item: (item[3], item[0]))
    output_dir = output_path.parent
    line_dir_link = relative_markdown_path(output_dir, line_output_dir)
    lines = ["# gcov Coverage", ""]
    lines.append(
        f"Line-coverage directory: [{line_dir_link}]({line_dir_link})")
    lines.append("")
    lines.extend(markdown_table("## Summary", summary_rows))
    lines.extend(
        [
            "",
            "## Files",
            "",
            "| File | Covered | Total | Line % | Line Data |",
            "| --- | ---: | ---: | ---: | --- |",
        ]
    )
    for path, covered, total, percent in sorted_rows:
        if path in line_files:
            line_file = line_output_dir / (path + ".gcov")
            line_link = relative_markdown_path(output_dir, line_file)
            line_cell = f"[gcov]({line_link})"
        else:
            # No detail file was written for this source (never compiled, or no
            # executable lines on this platform); avoid emitting a dead link.
            line_cell = "n/a"
        lines.append(
            f"| {path} | {covered} | {total} | {percent:.2f}% | {line_cell} |"
        )
    return "\n".join(lines) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments for the coverage run."""
    parser = argparse.ArgumentParser(
        description="Run gcov coverage and print a Markdown report."
    )
    parser.add_argument(
        "--build-dir",
        default="build",
        help="existing build directory used as a source of cached CMake options",
    )
    parser.add_argument(
        "--coverage-build-dir",
        default="build/gcov",
        help="build directory used for gcov-instrumented artifacts",
    )
    parser.add_argument(
        "--build-type",
        default="Debug",
        help="CMake build type for the coverage build (default: Debug)",
    )
    parser.add_argument(
        "--source-dir",
        action="append",
        dest="source_dirs",
        help=(
            "relative source directory to include in coverage; "
            "may be repeated (default: src)"
        ),
    )
    parser.add_argument(
        "--exclude-source-suffix",
        action="append",
        dest="exclude_source_suffixes",
        help=(
            "basename suffix to exclude from source discovery and gcov parsing; "
            "may be repeated (default: _test.c)"
        ),
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, os.cpu_count() or 1),
        help="parallel job count for build and test steps",
    )
    parser.add_argument(
        "--output",
        help="write Markdown output to this file (default: build/gcov.md)",
    )
    parser.add_argument(
        "--line-output-dir",
        help=(
            "directory for aggregated per-line .gcov files "
            "(default: <coverage-build-dir>/line-coverage)"
        ),
    )
    parser.add_argument(
        "--skip-configure",
        action="store_true",
        help="reuse an existing coverage build directory without re-running CMake",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="skip the build step",
    )
    parser.add_argument(
        "--skip-test",
        action="store_true",
        help="skip running CTest and use the existing coverage data files",
    )
    parser.add_argument(
        "--keep-gcda",
        action="store_true",
        help="do not delete old .gcda files before running tests",
    )
    parser.add_argument("--cmake", default="cmake",
                        help="cmake executable name")
    parser.add_argument("--ctest", default="ctest",
                        help="ctest executable name")
    parser.add_argument("--gcov", default="gcov", help="gcov executable name")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Configure, build, test, collect gcov data, and write the Markdown report."""
    args = parse_args(argv)
    cmake = ensure_tool(args.cmake)
    ctest = ensure_tool(args.ctest)
    gcov = ensure_tool(args.gcov)
    ensure_project_root(ROOT)

    base_build_dir = resolve_path(ROOT, args.build_dir)
    coverage_build_dir = resolve_path(ROOT, args.coverage_build_dir)
    output_path = (
        resolve_path(ROOT, args.output)
        if args.output
        else DEFAULT_MARKDOWN_OUTPUT.resolve()
    )
    line_output_dir = (
        resolve_path(ROOT, args.line_output_dir)
        if args.line_output_dir
        else coverage_build_dir / "line-coverage"
    )
    source_dirs = parse_source_dirs(args.source_dirs)
    exclude_source_suffixes = parse_exclude_source_suffixes(
        args.exclude_source_suffixes
    )
    base_cache = parse_cmake_cache(base_build_dir / "CMakeCache.txt")

    if not args.skip_configure:
        configure_command = build_configure_command(
            cmake, base_cache, coverage_build_dir, args.build_type
        )
        run_command(configure_command, cwd=ROOT)

    if not args.skip_build:
        run_command(
            [cmake, "--build", str(coverage_build_dir), f"-j{args.jobs}"],
            cwd=ROOT,
        )

    if not args.skip_test:
        if not args.keep_gcda:
            removed = remove_stale_gcda_files(coverage_build_dir)
            log(f"removed {removed} stale .gcda files")
        run_command(
            [
                ctest,
                "--test-dir",
                str(coverage_build_dir),
                "--output-on-failure",
                "-j",
                str(args.jobs),
            ],
            cwd=ROOT,
        )

    object_files = iter_object_files(coverage_build_dir)
    if not object_files:
        raise SystemExit(
            f"no instrumented object files found under {coverage_build_dir}")
    log(f"collecting gcov data from {len(object_files)} object files")
    coverage = collect_coverage(
        gcov,
        coverage_build_dir,
        object_files,
        source_dirs,
        exclude_source_suffixes,
    )
    rows = summarize_rows(
        iter_expected_sources(source_dirs, exclude_source_suffixes), coverage
    )
    line_files = write_line_coverage_files(line_output_dir, coverage, rows)
    log(f"wrote per-line coverage files to {line_output_dir}")
    report = render_markdown_report(
        rows,
        output_path=output_path,
        line_output_dir=line_output_dir,
        source_dirs=source_dirs,
        line_files=line_files,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    log(f"wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
