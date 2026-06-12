#!/usr/bin/env python3
"""Build the project with Release config and report per-file object file sizes.

Usage:
  scripts/codesize.py                  # build then report
  scripts/codesize.py -o PATH          # custom output file
  scripts/codesize.py --build DIR      # custom release build directory
  scripts/codesize.py --no-rebuild     # skip cmake configure and build steps

Output: build/codesize.md (Markdown table sorted by size, largest first)

Source files are discovered from compile_commands.json; every source whose
object file exists on disk is included (no regex filtering).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_RELEASE_BUILD_DIR = DEFAULT_BUILD_DIR / "codesize"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "codesize.md"

CACHE_LINE_RE = re.compile(r"^([A-Za-z0-9_]+):[^=]+=(.*)$")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def log(message: str) -> None:
    print(message, file=sys.stderr)


def ensure_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        sys.exit(f"error: required tool not found: {name}")
    return path


def ensure_project_root(root: Path) -> None:
    if not (root / "CMakeLists.txt").exists():
        sys.exit(
            f"error: working directory does not look like the project root: {
                root}"
        )


def parse_cmake_cache(cache_path: Path) -> dict[str, str]:
    cache: dict[str, str] = {}
    if not cache_path.exists():
        return cache
    with cache_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            m = CACHE_LINE_RE.match(line)
            if m:
                cache[m.group(1)] = m.group(2)
    return cache


def _human(n: int) -> str:
    """Return a concise human-readable byte count."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n / (1024 * 1024):.1f} MiB"


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_release(cmake: str, build_dir: Path, base_cache: dict[str, str], config: str) -> None:
    if build_dir.exists():
        log(
            f"Removing existing build directory {build_dir.relative_to(ROOT)} …")
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    configure_cmd = [
        cmake,
        "-S", str(ROOT),
        "-B", str(build_dir),
        f"-DCMAKE_BUILD_TYPE={config}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DENABLE_SANITIZERS=OFF",
        "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF",
    ]
    compiler = base_cache.get("CMAKE_C_COMPILER")
    if compiler:
        configure_cmd.append(f"-DCMAKE_C_COMPILER={compiler}")

    log("+ " + " ".join(configure_cmd))
    proc = subprocess.run(configure_cmd)
    if proc.returncode != 0:
        sys.exit(proc.returncode)

    jobs = os.cpu_count() or 1
    build_cmd = [cmake, "--build", str(build_dir), f"-j{jobs}"]
    log("+ " + " ".join(build_cmd))
    proc = subprocess.run(build_cmd)
    if proc.returncode != 0:
        sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# compile_commands.json helper
# ---------------------------------------------------------------------------

def _extract_obj(entry: dict) -> Path | None:
    """Return the object file path from a compile_commands.json entry.

    Prefer the ``arguments`` list when present; otherwise split ``command``.
    Handles both absolute and relative (relative to ``directory``) -o values.
    """
    args: list[str] = entry.get("arguments") or shlex.split(
        entry.get("command", ""))
    for i, arg in enumerate(args):
        if arg == "-o" and i + 1 < len(args):
            p = Path(args[i + 1])
            if not p.is_absolute():
                p = Path(entry["directory"]) / p
            return p
    return None


# ---------------------------------------------------------------------------
# SLOC counter
# ---------------------------------------------------------------------------

def _sloc(path: Path) -> int:
    """Count non-blank, non-comment source lines in a C file (approximate)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    count = 0
    in_block = False
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if in_block:
            if "*/" in s:
                s = s[s.index("*/") + 2:].strip()
                in_block = False
                if not s or s.startswith("//"):
                    continue
            else:
                continue
        # Strip inline block comments: /* ... */
        while "/*" in s:
            before, _, rest = s.partition("/*")
            if "*/" in rest:
                s = (before + " " + rest[rest.index("*/") + 2:]).strip()
            else:
                s = before.strip()
                in_block = True
                break
        if not s or s.startswith("//"):
            continue
        count += 1
    return count


# ---------------------------------------------------------------------------
# Size collection
# ---------------------------------------------------------------------------

def _resolve_linked_dirs(build_dir: Path, target: str) -> set[str]:
    """Return the CMakeFiles *.dir names for *target* and any linked static archives.

    Reads link.txt for the target, resolves each ``.a`` path, and derives the
    CMake target directory name from the archive stem (``libFOO.a`` → ``FOO.dir``).
    """
    primary = f"{target}.dir"
    dirs: set[str] = {primary}

    link_txt: Path | None = None
    for dirpath, _subdirs, filenames in os.walk(build_dir):
        if Path(dirpath).name == primary and "link.txt" in filenames:
            link_txt = Path(dirpath) / "link.txt"
            break
    if link_txt is None:
        return dirs

    # CMake runs the link command from the binary directory three levels above
    # link.txt: .../CMakeFiles/{target}.dir/link.txt → .../
    run_dir = link_txt.parent.parent.parent

    content = link_txt.read_text(encoding="utf-8", errors="replace")
    try:
        tokens = shlex.split(content)
    except ValueError:
        return dirs

    for token in tokens:
        p = Path(token)
        if p.suffix != ".a":
            continue
        resolved = (
            run_dir / p).resolve() if not p.is_absolute() else p.resolve()
        if not resolved.exists():
            continue
        stem = resolved.stem
        lib_name = stem[3:] if stem.startswith("lib") else stem
        dirs.add(f"{lib_name}.dir")

    return dirs


def _find_obj_files(build_dir: Path, target: str | None = None) -> dict[str, Path]:
    """Return {src_rel: obj_path} from compile_commands.json.

    When the same source appears in multiple entries (compiled into multiple
    targets), keep the entry with the largest object file.
    """
    db_path = build_dir / "compile_commands.json"
    if not db_path.exists():
        sys.exit(f"error: {db_path} not found — run cmake configure first")
    db: list[dict] = json.loads(db_path.read_text(encoding="utf-8"))

    target_dirs = _resolve_linked_dirs(
        build_dir, target) if target is not None else None
    best: dict[str, tuple[Path, int]] = {}
    for entry in db:
        src_abs = Path(entry["file"])
        try:
            src_rel = str(src_abs.relative_to(ROOT))
        except ValueError:
            continue
        obj = _extract_obj(entry)
        if obj is None or not obj.exists():
            continue
        if target_dirs is not None:
            parts = obj.parts
            try:
                idx = parts.index("CMakeFiles")
            except ValueError:
                continue
            if idx + 1 >= len(parts) or parts[idx + 1] not in target_dirs:
                continue
        sz = obj.stat().st_size
        if sz > best.get(src_rel, (None, 0))[1]:
            best[src_rel] = (obj, sz)
    return {src: obj for src, (obj, _) in best.items()}


def collect_sizes(build_dir: Path, target: str | None = None) -> list[tuple[str, int, int]]:
    """Return [(source_rel, byte_size, sloc), ...] from compile_commands.json."""
    obj_files = _find_obj_files(build_dir, target)
    return [(src, obj.stat().st_size, _sloc(ROOT / src)) for src, obj in obj_files.items()]


def collect_symbols(
    build_dir: Path, target: str | None = None
) -> list[tuple[str, int, str, str]]:
    """Return [(name, size_bytes, type_char, src_rel), ...] sorted by size descending.

    Runs ``nm --print-size --defined-only`` on every object file found in
    compile_commands.json.  Only symbols with non-zero size are included.
    Returns an empty list if ``nm`` is not available.
    """
    nm_path = shutil.which("nm")
    if nm_path is None:
        log("warning: nm not found; skipping symbol table")
        return []

    obj_files = _find_obj_files(build_dir, target)
    symbols: list[tuple[str, int, str, str]] = []
    for src_rel, obj in obj_files.items():
        try:
            proc = subprocess.run(
                [nm_path, "--print-size", "--defined-only", str(obj)],
                capture_output=True, text=True, check=False,
            )
        except OSError:
            continue
        for line in proc.stdout.splitlines():
            fields = line.split()
            # Defined symbols with a size field: addr size type name (≥4 fields)
            if len(fields) < 4:
                continue
            try:
                size = int(fields[1], 16)
            except ValueError:
                continue
            if size == 0:
                continue
            symbols.append((fields[3], size, fields[2], src_rel))
    symbols.sort(key=lambda x: -x[1])
    return symbols


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def write_report(
    rows: list[tuple[str, int, int]],
    symbols: list[tuple[str, int, str, str]],
    output: Path,
    elapsed: float,
    config: str,
) -> None:
    total_bytes = sum(sz for _, sz, _ in rows)
    total_sloc = sum(sl for _, _, sl in rows)
    date = datetime.date.today().isoformat()

    lines: list[str] = [
        "# Code Size Report",
        "",
        f"**Date:** {date} &ensp;"
        f" **Config:** {config} &ensp;"
        f" **Elapsed:** {elapsed:.1f} s &ensp;"
        f" **Files:** {len(rows)} &ensp;"
        f" **SLOC:** {total_sloc:,} &ensp;"
        f" **Total:** {total_bytes:,} B ({_human(total_bytes)})",
        "",
        "Sizes are unstripped Release-build object files (`*.c.o`)."
        " Sources are taken directly from `compile_commands.json`; every source"
        " whose object file exists on disk is included.",
        "",
        "| File | SLOC | Bytes | % |",
        "|---|---:|---:|---:|",
    ]
    for src, sz, sloc in sorted(rows, key=lambda x: (-x[1], x[0])):
        pct = sz / total_bytes * 100 if total_bytes else 0
        lines.append(f"| `{src}` | {sloc:,} | {sz:,} | {pct:.1f} |")
    lines.append(
        f"| **Total** | **{total_sloc:,}** | **{total_bytes:,}** | **100.0** |"
    )

    if symbols:
        total_sym_bytes = sum(sz for _, sz, _, _ in symbols)
        lines += [
            "",
            "## Symbols by Size",
            "",
            f"All defined symbols with non-zero size from"
            f" `nm --print-size --defined-only`, sorted largest first."
            f"  **{len(symbols):,}** symbols,"
            f" {total_sym_bytes:,} B ({_human(total_sym_bytes)}) total.",
            "",
            "| Symbol | Type | Bytes | Source |",
            "|---|:---:|---:|---|",
        ]
        for name, size, type_char, src in symbols:
            lines.append(f"| `{name}` | {type_char} | {size:,} | `{src}` |")

    lines.append("")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    log(f"wrote {output.relative_to(ROOT)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=str(DEFAULT_OUTPUT),
        help="output Markdown file (default: %(default)s)",
    )
    ap.add_argument(
        "--build",
        metavar="DIR",
        default=str(DEFAULT_RELEASE_BUILD_DIR),
        help="release build directory (default: %(default)s)",
    )
    ap.add_argument(
        "--config",
        metavar="TYPE",
        default="Release",
        help="cmake build type (default: %(default)s)",
    )
    ap.add_argument(
        "-t", "--target",
        metavar="TARGET",
        default=None,
        help="restrict report to sources compiled for cmake target TARGET",
    )
    ap.add_argument(
        "--no-rebuild",
        action="store_true",
        help="skip cmake configure and build steps",
    )
    args = ap.parse_args()

    ensure_project_root(ROOT)

    build_dir = Path(args.build)
    if not build_dir.is_absolute():
        build_dir = ROOT / build_dir
    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output

    t0 = time.monotonic()

    if not args.no_rebuild:
        cmake = ensure_tool("cmake")
        base_cache = parse_cmake_cache(DEFAULT_BUILD_DIR / "CMakeCache.txt")
        log(
            f"Configuring and building {args.config} in {build_dir.relative_to(ROOT)} …")
        build_release(cmake, build_dir, base_cache, args.config)

    log("Collecting object file sizes …")
    rows = collect_sizes(build_dir, target=args.target)
    if not rows:
        sys.exit(
            f"error: no compiled sources found via {build_dir / 'compile_commands.json'}")

    log("Collecting symbols via nm …")
    symbols = collect_symbols(build_dir, target=args.target)

    elapsed = time.monotonic() - t0
    log(f"{len(rows)} file(s), {sum(sl for _, _, sl in rows):,} SLOC, total {
        _human(sum(sz for _, sz, _ in rows))}, {elapsed:.1f} s")
    if symbols:
        log(f"{len(symbols):,} symbols, {
            _human(sum(sz for _, sz, _, _ in symbols))} total")

    write_report(rows, symbols, output, elapsed, args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
