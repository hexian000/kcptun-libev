#!/usr/bin/env python3
# csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
# This code is licensed under MIT license (see LICENSE for details)
"""Build a target and analyze the linked binary's size.

The report breaks the *linked* executable down along four dimensions:

  * Sections  -- ELF output sections (.text, .rodata, .data, .bss, ...).
  * Modules   -- bytes attributed to each source file / linked archive.
  * Functions -- per-function code size.
  * Data      -- per-datum read-only/writable/zero-init size.

Unlike a per-object-file report, this reflects what actually ships: the
release build compiles with ``-ffunction-sections -fdata-sections`` and links
with ``--gc-sections``, so a linker map file (``-Wl,-Map``) lists exactly the
input sections that survived, each with its size and origin object. Dead code
the linker discarded never appears.

Usage:
  scripts/codesize.py                  # analyze the main executable
  scripts/codesize.py -t NAME          # analyze executable target NAME
  scripts/codesize.py --config Release # cmake build type (default: Release)
  scripts/codesize.py --lto on         # force link-time optimization on/off/auto
  scripts/codesize.py --no-rebuild     # reuse an existing analysis build

Output: build/codesize.md (four Markdown tables, each sorted largest first).

The main executable is the executable target named after the project; in a
library project with no such target, pass ``-t NAME`` to name one (e.g. a test
or example binary). The tool is project-agnostic: everything is discovered from
CMakeCache.txt, the target link commands, compile_commands.json, and the map.
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
from dataclasses import dataclass
from pathlib import Path


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_ANALYSIS_BUILD_DIR = DEFAULT_BUILD_DIR / "codesize"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "codesize.md"
MAP_NAME = "codesize.map"

CACHE_LINE_RE = re.compile(r"^([A-Za-z0-9_]+):[^=]+=(.*)$")

# GNU ld map-file grammar (section "Linker script and memory map").
_MAP_GATE = "Linker script and memory map"
# An input section is indented one space and carries an origin object; ld wraps
# the origin onto the next line when the section name is too long, so also match
# a bare indented name followed by a continuation line.
_IN_SEC_RE = re.compile(
    r"^ (\.\S+)\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+(\S.*)$")
_IN_NAME_RE = re.compile(r"^ (\.\S+)\s*$")
_IN_CONT_RE = re.compile(r"^\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+(\S.*)$")
# ld annotates a section resized by linker relaxation with a secondary
# "0xNN (size before relaxing)" line. For a mergeable string/constant pool
# (SHF_MERGE), the main size column is the whole merged pool charged to its
# first contributor while this pre-relaxing value is the section's own input
# size -- the honest per-module attribution. See parse_map().
_IN_RELAX_RE = re.compile(r"^\s+0x([0-9a-fA-F]+)\s+\(size before relaxing\)\s*$")
# An archive-member origin: "path/to/libFOO.a(bar.c.o)".
_ARCHIVE_RE = re.compile(r"^(?P<archive>.+\.a)\((?P<member>[^)]+)\)$")
# LTO recompilation temporaries carry no source identity: GCC emits a single
# "ccXXXX.lto.o" for a whole-program link, or "ccXXXX.ltransN.o" when partitioned.
_LTRANS_RE = re.compile(r"\.(?:lto|ltrans\d*)\.o$")

# Read-only/writable/zero-init input-section prefixes, longest first so that
# ".data.rel.ro." wins over ".data.".
_DATA_PREFIXES = (
    ".data.rel.ro.", ".rodata.", ".data.", ".bss.",
    ".tdata.", ".tbss.", ".sdata.", ".sbss.",
)
# ".text" cold/hot/startup partitions of a function FOO ("foo.cold" etc.).
_TEXT_PARTS = ("unlikely.", "hot.", "startup.", "exit.")
# Anonymous merged constant pools (SHF_MERGE), e.g. ".rodata.str1.8",
# ".rodata.cst8", or a function-local ".rodata.<fn>.str1.1": not a named datum.
_POOL_RE = re.compile(r"\.(?:str\d+\.\d+|cst\d+)(?:\.|$)")

LTO_MODULE = "(link-time optimized)"
RUNTIME_MODULE = "(runtime/linker)"

# Sections the linker synthesizes for the whole image (relocations, PLT/GOT,
# dynamic-linking tables, the unwind-index header, per-object notes). They have
# no single owning translation unit, and ld charges them to the first input
# object in the map, so they are bucketed together rather than blamed on it.
# ``.eh_frame`` itself is deliberately left off: it carries real per-object
# unwind data and is more useful attributed to the module that brought it.
_RUNTIME_PREFIXES = (
    ".plt", ".got", ".rela", ".rel.", ".dynsym", ".dynstr", ".dynamic",
    ".hash", ".gnu.hash", ".gnu.version", ".interp", ".eh_frame_hdr", ".note",
)
# Non-allocated sections: present in the objects/map but not in the loaded
# image (and excluded from `size`'s allocated total), so dropped entirely.
_NONALLOC_PREFIXES = (
    ".comment", ".debug", ".symtab", ".strtab", ".shstrtab",
    ".gnu_debuglink", ".gnu.attributes",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def log(message: str) -> None:
    """Print *message* to stderr."""
    print(message, file=sys.stderr)


def _display_path(p: Path) -> str:
    """Format *p* relative to ROOT for logging, falling back to absolute."""
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def ensure_tool(name: str) -> str:
    """Return the path to tool *name*, exiting if it is not on PATH."""
    path = shutil.which(name)
    if path is None:
        sys.exit(f"error: required tool not found: {name}")
    return path


def ensure_project_root(root: Path) -> None:
    """Exit unless *root* looks like the project root (has CMakeLists.txt)."""
    if not (root / "CMakeLists.txt").exists():
        sys.exit(
            "error: working directory does not look like the project "
            f"root: {root}"
        )


def parse_cmake_cache(cache_path: Path) -> dict[str, str]:
    """Parse a CMakeCache.txt file into a ``{name: value}`` dict."""
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


def _pct(n: int, total: int) -> float:
    """Return *n* as a percentage of *total* (0 when *total* is 0)."""
    return n / total * 100.0 if total else 0.0


def _run(command: list[str]) -> None:
    """Run *command*, echoing it; exit with its status on failure."""
    log("+ " + " ".join(command))
    proc = subprocess.run(command, check=False)
    if proc.returncode != 0:
        sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# compile_commands.json index (object file -> source)
# ---------------------------------------------------------------------------


def _extract_obj(entry: dict) -> Path | None:
    """Return the object-file path from a compile_commands.json entry."""
    args: list[str] = entry.get("arguments") or shlex.split(
        entry.get("command", ""))
    for i, arg in enumerate(args):
        if arg == "-o" and i + 1 < len(args):
            p = Path(args[i + 1])
            if not p.is_absolute():
                p = Path(entry["directory"]) / p
            return p
    return None


def _cmakefiles_dir(parts: tuple[str, ...]) -> str | None:
    """Return the ``CMakeFiles/<name>.dir`` component from a path's *parts*."""
    try:
        idx = parts.index("CMakeFiles")
    except ValueError:
        return None
    if idx + 1 >= len(parts):
        return None
    name = parts[idx + 1]
    return name if name.endswith(".dir") else None


@dataclass
class ObjectIndex:
    """Object-file -> source-file lookups derived from compile_commands.json.

    Three keys, tried in order of specificity: the resolved object path, the
    ``(<target>.dir, basename)`` pair (so an archive member resolves via the
    library's build directory), and a unique basename fallback.
    """

    by_abspath: dict[str, str]
    by_dirbase: dict[tuple[str, str], str]
    by_base: dict[str, str | None]  # None marks an ambiguous basename


def build_object_index(db: list[dict]) -> ObjectIndex:
    """Build the object->source :class:`ObjectIndex` from *db* entries."""
    by_abspath: dict[str, str] = {}
    by_dirbase: dict[tuple[str, str], str] = {}
    by_base: dict[str, str | None] = {}
    for entry in db:
        obj = _extract_obj(entry)
        if obj is None:
            continue
        try:
            src_rel = str(Path(entry["file"]).resolve().relative_to(ROOT))
        except (KeyError, ValueError):
            continue
        by_abspath[str(obj.resolve())] = src_rel
        cmdir = _cmakefiles_dir(obj.parts)
        if cmdir is not None:
            by_dirbase[(cmdir, obj.name)] = src_rel
        by_base[obj.name] = src_rel if obj.name not in by_base else (
            by_base[obj.name] if by_base[obj.name] == src_rel else None)
    return ObjectIndex(by_abspath, by_dirbase, by_base)


def attribute_module(origin: str, index: ObjectIndex, link_dir: Path) -> str:
    """Map a map-file *origin* token to a source file or a library label.

    In-tree objects resolve to their repo-relative source; a linked archive
    with no source mapping (e.g. a prebuilt ``liblua.a``) is labeled by the
    archive basename; LTO temporaries collapse to a single bucket.
    """
    if _LTRANS_RE.search(origin):
        return LTO_MODULE
    m = _ARCHIVE_RE.match(origin)
    if m is not None:
        member = m.group("member")
        stem = Path(m.group("archive")).stem
        lib_dir = f"{stem[3:] if stem.startswith('lib') else stem}.dir"
        src = index.by_dirbase.get((lib_dir, member))
        if src is None and index.by_base.get(member):
            src = index.by_base[member]
        return src if src is not None else Path(m.group("archive")).name
    obj = Path(origin)
    resolved = str((obj if obj.is_absolute() else link_dir / obj).resolve())
    src = index.by_abspath.get(resolved)
    if src is None:
        cmdir = _cmakefiles_dir(obj.parts)
        if cmdir is not None:
            src = index.by_dirbase.get((cmdir, obj.name))
    if src is None and index.by_base.get(obj.name):
        src = index.by_base[obj.name]
    return src if src is not None else obj.name


# ---------------------------------------------------------------------------
# CMake targets: configure, classify, select, build
# ---------------------------------------------------------------------------


@dataclass
class Target:
    """A CMake target as seen through its generated link command."""

    name: str
    kind: str        # "exe" or "lib"
    link_txt: Path


def _find_output(argv: list[str]) -> str | None:
    """Return the ``-o`` output token from a split link command line."""
    for i, arg in enumerate(argv):
        if arg == "-o" and i + 1 < len(argv):
            return argv[i + 1]
    return None


def classify_targets(build_dir: Path) -> dict[str, Target]:
    """Return ``{name: Target}`` for every linked target in *build_dir*.

    Reads the target directories CMake records, then each ``link.txt``: an
    archiver command builds a library, any other link whose output is not a
    ``.a``/``.so`` builds an executable. Targets without a ``link.txt``
    (utility/interface targets) are skipped.
    """
    listing = build_dir / "CMakeFiles" / "TargetDirectories.txt"
    if not listing.exists():
        return {}
    targets: dict[str, Target] = {}
    for line in listing.read_text(
            encoding="utf-8", errors="replace").splitlines():
        target_dir = Path(line.strip())
        if not target_dir.name.endswith(".dir"):
            continue
        link_txt = target_dir / "link.txt"
        if not link_txt.exists():
            continue
        name = target_dir.name[:-len(".dir")]
        argv = shlex.split(link_txt.read_text(encoding="utf-8", errors="replace"))
        if not argv:
            continue
        launcher = Path(argv[0]).name
        output = _find_output(argv) or ""
        if launcher == "ar" or launcher.endswith("-ar") or output.endswith(".a"):
            kind = "lib"
        elif output.endswith(".so") or ".so." in output:
            kind = "lib"
        else:
            kind = "exe"
        targets[name] = Target(name, kind, link_txt)
    return targets


def select_target(
    targets: dict[str, Target], cache: dict[str, str], requested: str | None
) -> Target:
    """Choose the executable to analyze, exiting with guidance on failure."""
    executables = sorted(n for n, t in targets.items() if t.kind == "exe")
    if requested is not None:
        target = targets.get(requested)
        if target is None:
            sys.exit(
                f"error: unknown target: {requested}\n"
                f"available executables: {', '.join(executables) or '(none)'}")
        if target.kind != "exe":
            sys.exit(f"error: target is not an executable: {requested}")
        return target
    project = cache.get("CMAKE_PROJECT_NAME")
    if project and project in targets and targets[project].kind == "exe":
        return targets[project]
    if len(executables) == 1:
        return targets[executables[0]]
    sys.exit(
        f"error: no main executable (project '{project or '?'}' builds a "
        "library); pass -t NAME to choose one.\n"
        f"available executables: {', '.join(executables) or '(none)'}")


def configure(
    cmake: str, build_dir: Path, base_cache: dict[str, str],
    config: str, lto: str, map_path: Path,
) -> None:
    """Configure a fresh analysis build with map generation enabled."""
    if build_dir.exists():
        log(f"Removing existing build directory {_display_path(build_dir)} ...")
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)
    command = [
        cmake,
        "-S", str(ROOT),
        "-B", str(build_dir),
        # A generator that writes per-target link.txt, so target classification
        # and the linked-binary/map paths are discoverable regardless of the
        # user's own build generator.
        "-G", "Unix Makefiles",
        f"-DCMAKE_BUILD_TYPE={config}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DENABLE_SANITIZERS=OFF",
        f"-DCMAKE_EXE_LINKER_FLAGS=-Wl,-Map={map_path}",
    ]
    if lto == "on":
        command.append("-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON")
    elif lto == "off":
        command.append("-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF")
    else:  # auto: inherit the reference build's setting when it has one
        ipo = base_cache.get("CMAKE_INTERPROCEDURAL_OPTIMIZATION")
        if ipo:
            command.append(f"-DCMAKE_INTERPROCEDURAL_OPTIMIZATION={ipo}")
    compiler = base_cache.get("CMAKE_C_COMPILER")
    if compiler:
        command.append(f"-DCMAKE_C_COMPILER={compiler}")
    _run(command)


def detect_lto(target: Target) -> bool:
    """Return whether *target*'s link command enables LTO."""
    return "-flto" in target.link_txt.read_text(
        encoding="utf-8", errors="replace")


def target_binary(target: Target) -> Path:
    """Return the linked binary path produced by *target*'s link command.

    CMake runs the link from the directory three levels above ``link.txt``
    (``.../CMakeFiles/<t>.dir/link.txt``); the ``-o`` token is relative to it.
    """
    link_dir = target.link_txt.parent.parent.parent
    argv = shlex.split(target.link_txt.read_text(
        encoding="utf-8", errors="replace"))
    output = _find_output(argv)
    if output is None:
        sys.exit(f"error: no output in link command for {target.name}")
    out = Path(output)
    return out if out.is_absolute() else (link_dir / out).resolve()


# ---------------------------------------------------------------------------
# Map file parsing and section classification
# ---------------------------------------------------------------------------


@dataclass
class InputSection:
    """A kept input section: its name, size in bytes, and origin object."""

    name: str
    size: int
    origin: str


def parse_map(map_path: Path) -> list[InputSection]:
    """Parse *map_path* into the list of kept input sections.

    Only the "Linker script and memory map" region is read, so garbage-
    collected sections (listed earlier under "Discarded input sections") are
    excluded by construction. Handles ld's line wrapping of long section names.

    For a mergeable string/constant pool, ld charges the whole deduplicated
    pool to its first contributor's section and lists every other contributor
    separately too, so the raw sizes both misattribute the pool and double-count
    it. Where ld emits a "(size before relaxing)" note for such a pool, that
    pre-merge value is used instead: the per-module attribution stays honest and
    the pool is no longer counted twice.
    """
    if not map_path.exists():
        sys.exit(
            f"error: map file not found: {_display_path(map_path)} "
            "(the target may not have relinked; drop --no-rebuild)")
    sections: list[InputSection] = []
    in_map = False
    pending: str | None = None  # a wrapped input-section name awaiting its size
    for raw in map_path.read_text(
            encoding="utf-8", errors="replace").splitlines():
        if not in_map:
            if _MAP_GATE in raw:
                in_map = True
            continue
        m = _IN_RELAX_RE.match(raw)
        if m is not None:
            # Refines the section just recorded; only trust it for merge pools,
            # where the main size is the whole pool and this is the own size.
            if sections and _POOL_RE.search(sections[-1].name):
                sections[-1].size = int(m.group(1), 16)
            continue
        if pending is not None:
            m = _IN_CONT_RE.match(raw)
            if m is not None:
                sections.append(InputSection(
                    pending, int(m.group(1), 16), m.group(2).split()[0]))
            pending = None
            if m is not None:
                continue
        m = _IN_SEC_RE.match(raw)
        if m is not None:
            sections.append(InputSection(
                m.group(1), int(m.group(2), 16), m.group(3).split()[0]))
            continue
        m = _IN_NAME_RE.match(raw)
        if m is not None:
            pending = m.group(1)
    return sections


def classify_section(name: str) -> tuple[str | None, str | None]:
    """Return ``(dimension, symbol)`` for input-section *name*.

    Dimension is ``"func"`` for code, ``"data"`` for read-only/writable/zero-
    init data, or None for sections that belong to neither table (CRT glue,
    linker-generated tables). Symbol is None for anonymous merged pools.
    """
    if name.startswith(".text."):
        rest = name[len(".text."):]
        for part in _TEXT_PARTS:
            if rest.startswith(part):
                rest = rest[len(part):]
                break
        return "func", (rest or None)
    for prefix in _DATA_PREFIXES:
        if name.startswith(prefix):
            if _POOL_RE.search(name):
                return "data", None
            return "data", (name[len(prefix):] or None)
    return None, None


def _data_kind(name: str) -> str:
    """Return a short storage label for a data section name."""
    if name.startswith(".rodata"):
        return "rodata"
    if name.startswith(".data.rel.ro"):
        return "rel.ro"
    if name.startswith((".bss", ".tbss", ".sbss")):
        return "bss"
    if name.startswith((".tdata",)):
        return "tdata"
    return "data"


# ---------------------------------------------------------------------------
# Section sizes from `size`
# ---------------------------------------------------------------------------


def _section_kind(name: str) -> str:
    """Bucket an ELF output section into code/data/bss/ro-data for display."""
    if name.startswith(".text") or name in (".init", ".fini", ".plt") \
            or name.startswith(".plt"):
        return "code"
    if name.startswith((".bss", ".tbss", ".sbss")):
        return "bss"
    if name.startswith((".data", ".got", ".tdata", ".sdata")) \
            or name in (".dynamic", ".init_array", ".fini_array"):
        return "data"
    return "ro-data"


def size_sections(size_tool: str, binary: Path) -> list[tuple[str, str, int]]:
    """Return ``(section, kind, bytes)`` rows for the *allocated* sections.

    Parses ``size -A -d`` and keeps only sections with a load address, i.e. the
    ones that occupy the running image; non-allocated metadata (``.comment``,
    ``.symtab``, ``.shstrtab``) is excluded so the total is the shipped size.
    """
    proc = subprocess.run(
        [size_tool, "-A", "-d", str(binary)],
        capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.exit(f"error: size failed on {_display_path(binary)}")
    rows: list[tuple[str, str, int]] = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].startswith("."):
            continue
        try:
            size, addr = int(fields[1]), int(fields[2])
        except ValueError:
            continue
        if size and addr:
            rows.append((fields[0], _section_kind(fields[0]), size))
    return rows


# ---------------------------------------------------------------------------
# Table assembly
# ---------------------------------------------------------------------------


@dataclass
class Tables:
    """The four size-sorted dimensions of the report, each ``(label..., bytes)``."""

    sections: list[tuple[str, str, int]]
    modules: list[tuple[str, int]]
    functions: list[tuple[str, str, int]]
    data: list[tuple[str, str, str, int]]


def build_tables(
    sections: list[InputSection], size_rows: list[tuple[str, str, int]],
    index: ObjectIndex, link_dir: Path,
) -> Tables:
    """Aggregate parsed input sections + `size` rows into the four tables."""
    modules: dict[str, int] = {}
    functions: dict[tuple[str, str], int] = {}
    data: dict[tuple[str, str, str], int] = {}
    for sec in sections:
        if sec.size <= 0 or sec.name.startswith(_NONALLOC_PREFIXES):
            continue
        if sec.name.startswith(_RUNTIME_PREFIXES):
            module = RUNTIME_MODULE
        else:
            module = attribute_module(sec.origin, index, link_dir)
        modules[module] = modules.get(module, 0) + sec.size
        dim, symbol = classify_section(sec.name)
        if dim == "func":
            key = (symbol or "(anonymous)", module)
            functions[key] = functions.get(key, 0) + sec.size
        elif dim == "data":
            dkey = (symbol or "(string/const pool)",
                    _data_kind(sec.name), module)
            data[dkey] = data.get(dkey, 0) + sec.size
    return Tables(
        sections=sorted(size_rows, key=lambda r: (-r[2], r[0])),
        modules=sorted(
            ((m, n) for m, n in modules.items()), key=lambda r: (-r[1], r[0])),
        functions=sorted(
            ((s, m, n) for (s, m), n in functions.items()),
            key=lambda r: (-r[2], r[0])),
        data=sorted(
            ((s, k, m, n) for (s, k, m), n in data.items()),
            key=lambda r: (-r[3], r[0])),
    )


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _table(
    title: str, note: str, headers: list[str], aligns: str,
    rows: list[tuple], total: int,
) -> list[str]:
    """Render one titled Markdown table; the last column is bytes + percent.

    Every row is ``(label, ..., size)``: all but the last field are label
    columns, the last is the byte count rendered with a percent-of-*total*.
    """
    lines = [title, ""]
    if note:
        lines += [note, ""]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + aligns + "|")
    for row in rows:
        *labels, size = row
        cells = " | ".join(f"`{c}`" for c in labels)
        lines.append(f"| {cells} | {size:,} | {_pct(size, total):.1f} |")
    n_labels = len(headers) - 2  # columns before Bytes and %
    total_cells = ["**Total**"] + [""] * (n_labels - 1)
    lines.append(
        "| " + " | ".join(total_cells) + f" | **{total:,}** | **100.0** |")
    lines.append("")
    return lines


def render_report(meta: dict[str, str], tables: Tables) -> str:
    """Render the full four-table Markdown report."""
    sec_total = sum(sz for _, _, sz in tables.sections)
    fn_total = sum(sz for _, _, sz in tables.functions)
    data_total = sum(sz for _, _, _, sz in tables.data)
    mod_total = sum(sz for _, sz in tables.modules)

    lines = [
        "# Code Size Report",
        "",
        f"**Date:** {meta['date']} &ensp;"
        f" **Config:** {meta['config']} &ensp;"
        f" **LTO:** {meta['lto']} &ensp;"
        f" **Target:** {meta['target']} &ensp;"
        f" **File size:** {meta['file_size']} &ensp;"
        f" **Linked:** {sec_total:,} B ({_human(sec_total)})",
        "",
        "Sizes come from the linked binary's map file — only the input "
        "sections that survived `--gc-sections` — with allocated section totals "
        "from `size`, which is authoritative. Module/Function/Data are "
        "per-symbol attributions: the linker deduplicates identical "
        "string/constant literals across modules and these are counted "
        "pre-merge per owning module, so their totals can differ from the "
        "section total by a few percent.",
        "",
    ]
    lines += _table(
        "## Sections", "",
        ["Section", "Kind", "Bytes", "%"], "---|:-:|---:|---:",
        [(s, k, sz) for s, k, sz in tables.sections], sec_total)
    lines += _table(
        "## Modules", "",
        ["Module", "Bytes", "%"], "---|---:|---:",
        list(tables.modules), mod_total)
    lines += _table(
        "## Functions", "",
        ["Function", "Module", "Bytes", "%"], "---|---|---:|---:",
        list(tables.functions), fn_total)
    lines += _table(
        "## Data", meta.get("data_note", ""),
        ["Symbol", "Sec", "Module", "Bytes", "%"], "---|:-:|---|---:|---:",
        list(tables.data), data_total)
    if meta.get("lto_note"):
        lines += [meta["lto_note"], ""]
    return "\n".join(lines)


def write_report(text: str, output: Path) -> None:
    """Write *text* to *output*, creating parent directories."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    log(f"wrote {_display_path(output)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Configure, build a target, analyze the linked binary, write the report."""
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "-o", "--output", metavar="FILE", default=str(DEFAULT_OUTPUT),
        help="output Markdown file (default: %(default)s)")
    ap.add_argument(
        "--build", metavar="DIR", default=str(DEFAULT_ANALYSIS_BUILD_DIR),
        help="analysis build directory (default: %(default)s)")
    ap.add_argument(
        "--config", metavar="TYPE", default="Release",
        help="cmake build type (default: %(default)s)")
    ap.add_argument(
        "-t", "--target", metavar="NAME", default=None,
        help="executable target to analyze (default: the main executable)")
    ap.add_argument(
        "--lto", choices=("auto", "on", "off"), default="auto",
        help="link-time optimization: on, off, or inherit from build/ "
             "(default: %(default)s)")
    ap.add_argument(
        "--no-rebuild", action="store_true",
        help="reuse an existing analysis build instead of reconfiguring")
    args = ap.parse_args()

    ensure_project_root(ROOT)
    cmake = ensure_tool("cmake")
    size_tool = ensure_tool("size")

    build_dir = Path(args.build)
    if not build_dir.is_absolute():
        build_dir = ROOT / build_dir
    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    map_path = build_dir / MAP_NAME

    t0 = time.monotonic()
    base_cache = parse_cmake_cache(DEFAULT_BUILD_DIR / "CMakeCache.txt")
    if not args.no_rebuild:
        log(f"Configuring {args.config} in {_display_path(build_dir)} ...")
        configure(cmake, build_dir, base_cache, args.config, args.lto, map_path)

    cache = parse_cmake_cache(build_dir / "CMakeCache.txt")
    targets = classify_targets(build_dir)
    if not targets:
        sys.exit(f"error: no CMake targets found in {_display_path(build_dir)} "
                 "-- configure first (drop --no-rebuild)")
    target = select_target(targets, cache, args.target)

    if not args.no_rebuild:
        log(f"Building target {target.name} ...")
        if map_path.exists():
            map_path.unlink()
        _run([cmake, "--build", str(build_dir),
              "--target", target.name, f"-j{os.cpu_count() or 1}"])

    binary = target_binary(target)
    lto = detect_lto(target) or args.lto == "on"
    link_dir = target.link_txt.parent.parent.parent

    log("Parsing map and section sizes ...")
    sections = parse_map(map_path)
    size_rows = size_sections(size_tool, binary)
    index = build_object_index(
        json.loads((build_dir / "compile_commands.json").read_text(
            encoding="utf-8")))
    tables = build_tables(sections, size_rows, index, link_dir)

    meta = {
        "date": datetime.date.today().isoformat(),
        "config": args.config,
        "lto": "on" if lto else "off",
        "target": target.name,
        "file_size": _human(binary.stat().st_size),
    }
    if lto:
        meta["lto_note"] = (
            "> **LTO is on.** Sections, Functions and Data reflect the "
            "optimized binary, but per-source **module** attribution collapses "
            f"under LTO (origins are recompilation temporaries → `{LTO_MODULE}`)."
        )
    text = render_report(meta, tables)
    write_report(text, output)

    elapsed = time.monotonic() - t0
    sec_total = sum(sz for _, _, sz in tables.sections)
    log(f"{target.name}: {len(tables.modules)} module(s), "
        f"{len(tables.functions)} function(s), linked {_human(sec_total)}, "
        f"{elapsed:.1f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
