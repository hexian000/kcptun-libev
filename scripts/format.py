#!/usr/bin/env python3
"""scripts/format.py

Apply formatting conventions to the repository:

  * clang-format to .c/.h files under src/;
  * a cpp-cleanup pass on the same files: #include reordering/classification,
    #endif conditional annotation, and an include-dependency lint
    (see below);
  * Unicode normalization (NFC by default, or NFKC with --nfkc) to all
    git-tracked text files.

The repository's standard text encoding is UTF-8, no BOM.  A file that does
not look like UTF-8-no-BOM (a BOM, embedded NUL bytes, or invalid UTF-8) is
never processed -- it is left untouched and reported with a warning instead.

Include classification is derived, not hardcoded: each #include is resolved
against the compilation database (compile_commands.json) and bucketed by
*where the header actually lives* (project tree vs in-tree contrib vs an
installed/system directory); a built-in table of C-standard/POSIX headers
separates the standard group from installed third-party libraries.  When the
database is absent, resolution falls back to structural heuristics.

Include groups (blank-line separated, alphabetically sorted within each):

  1. associated header (foo.h for foo.c, or foo_test.c; omitted in headers) "..."
  2. project headers (resolve inside the repo)                        "..."
  3. in-tree contrib / third-party (resolve under contrib/ etc.)       "..."
  4. platform / installed third-party (angle-bracket, not recognized)  <...>
  5. standard C / POSIX (angle-bracket, recognized)                    <...>

Conditional #include blocks (#if ... #endif) stay contiguous and sort by
their first contained #include.  The cpp-cleanup pass also covers the rest of
the convention:

  * #endif closing a block that spans 10 or more lines, or that nests
    another conditional, gains a /* CONDITION */ annotation when it lacks a
    trailing comment (add-only);
  * a warning is printed when a project header include creates a recursive
    dependency between directories;
  * a warning is printed when a header under an internal/ directory is
    included from outside the tree rooted at internal's parent (Go's
    internal/ convention).

Usage:
    python3 scripts/format.py [--check] [--nfkc] [ROOT]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import types
import unicodedata
from pathlib import Path

# ---------------------------------------------------------------------------
# File iteration
# ---------------------------------------------------------------------------


def iter_c_files(root: Path):
    """Yield .c/.h files under root/src/, excluding *.gen.[ch]."""
    src = root / "src"
    for pattern in ("**/*.c", "**/*.h"):
        yield from (
            p for p in src.glob(pattern)
            if not p.name.endswith((".gen.c", ".gen.h"))
        )


def iter_text_files(root: Path):
    """Yield git-tracked files under root, excluding contrib/ (third-party)."""
    out = subprocess.run(
        ["git", "ls-files"],
        capture_output=True, text=True, check=True, cwd=str(root),
    ).stdout
    for line in out.splitlines():
        if line.startswith("contrib/"):
            continue
        p = root / line
        if p.is_file():
            yield p


def _warn(message: str) -> None:
    print(f"format: {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Encoding check: the repository's standard text format is UTF-8, no BOM.
# ---------------------------------------------------------------------------

# Ordered longest-prefix-first: UTF-32 BOMs share a 2-byte prefix with the
# corresponding UTF-16 BOM, so the 4-byte signatures must be tried first.
_BOM_SIGNATURES = (
    (b"\x00\x00\xfe\xff", "UTF-32BE BOM"),
    (b"\xff\xfe\x00\x00", "UTF-32LE BOM"),
    (b"\xfe\xff", "UTF-16BE BOM"),
    (b"\xff\xfe", "UTF-16LE BOM"),
    (b"\xef\xbb\xbf", "UTF-8 BOM"),
)


def _utf8_nobom_issue(data: bytes) -> str | None:
    """Return why *data* is not UTF-8-no-BOM text, or None if it is."""
    for sig, name in _BOM_SIGNATURES:
        if data.startswith(sig):
            return f"starts with a {name}"
    if b"\x00" in data:
        return "contains NUL bytes"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return f"not valid UTF-8 ({exc})"
    return None


# ---------------------------------------------------------------------------
# clang-format pass
# ---------------------------------------------------------------------------


def _clang_version_ok(version: str) -> bool:
    """Return True if clang-format is available and its version matches exactly."""
    if shutil.which("clang-format") is None:
        return False
    try:
        out = subprocess.run(
            ["clang-format", "--version"],
            capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return False
    # Expected: "clang-format version 18.1.8" or "Ubuntu clang-format version 18.1.8"
    return bool(re.search(rf"version {re.escape(version)}(?:\s|$)", out))


def _clang_format_file(path: Path, root: Path) -> bytes:
    """Return the clang-format output for *path* (clang-format reads the file)."""
    return subprocess.run(
        ["clang-format", str(path)],
        capture_output=True, check=True, cwd=str(root),
    ).stdout


# ---------------------------------------------------------------------------
# cpp-cleanup pass: built-in classification knowledge (universal, not
# project-specific)
# ---------------------------------------------------------------------------

# ISO C (C89-C23) and POSIX headers -> group 5 ("standard C / POSIX").
#
# This intentionally OMITS optional / feature-gated system facilities that are
# conventionally grouped with platform libraries rather than the language
# runtime (e.g. <syslog.h>, <execinfo.h>).  Any angle-bracket header not
# listed here counts as platform third-party (group 4).
_STD_HEADERS = frozenset({
    # ISO C
    "assert.h", "complex.h", "ctype.h", "errno.h", "fenv.h", "float.h",
    "inttypes.h", "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h",
    "signal.h", "stdalign.h", "stdarg.h", "stdatomic.h", "stdbit.h",
    "stdbool.h", "stdckdint.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h",
    "stdnoreturn.h", "string.h", "tgmath.h", "threads.h", "time.h", "uchar.h",
    "wchar.h", "wctype.h",
    # POSIX (single-file)
    "aio.h", "cpio.h", "dirent.h", "dlfcn.h", "fcntl.h", "fmtmsg.h",
    "fnmatch.h", "ftw.h", "glob.h", "grp.h", "iconv.h", "langinfo.h",
    "libgen.h", "monetary.h", "mqueue.h", "ndbm.h", "netdb.h", "nl_types.h",
    "poll.h", "pthread.h", "pwd.h", "regex.h", "sched.h", "search.h",
    "semaphore.h", "spawn.h", "strings.h", "tar.h", "termios.h", "trace.h",
    "ulimit.h", "unistd.h", "utime.h", "utmpx.h", "wordexp.h",
})

# POSIX header subdirectories -> group 5 (e.g. <sys/socket.h>, <arpa/inet.h>).
_STD_DIR_PREFIXES = ("sys/", "arpa/", "net/", "netinet/")

# Directory names that mark an in-tree third-party dependency (group 3).
_DEFAULT_CONTRIB_DIRS = frozenset({
    "contrib", "vendor", "third_party", "thirdparty", "3rdparty", "external",
    "deps", "subprojects",
})

# Directory name marking an internal-only subtree, Go-style: a header under
# .../x/internal/... may be included only from within the tree rooted at x
# (internal's parent), never from outside it.  See _internal_boundary().
_INTERNAL_DIR = "internal"

# Translation-unit extensions whose associated header is <stem>.h (group 1).
_C_SOURCE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm")

# Annotate a conditional once its span (opener to #endif) reaches this many
# lines; see annotate_conditionals().
_COND_MIN_LINES = 10

GROUP_ASSOCIATED = 1
GROUP_PROJECT = 2
GROUP_CONTRIB = 3
GROUP_PLATFORM = 4
GROUP_STANDARD = 5
NUM_GROUPS = 5


def _is_standard(name: str) -> bool:
    """True if *name* (e.g. ``stdio.h`` or ``sys/socket.h``) is C/POSIX."""
    return name in _STD_HEADERS or name.startswith(_STD_DIR_PREFIXES)


# ---------------------------------------------------------------------------
# cpp-cleanup pass: small path helpers
# ---------------------------------------------------------------------------

def _norm(path) -> str:
    return os.path.normpath(os.path.abspath(path))


def _find_repo_root(start):
    """Walk up from *start* to the nearest ancestor containing ``.git``."""
    p = Path(start).resolve()
    for d in (p, *p.parents):
        if (d / ".git").exists():
            return d
    return None


def _is_inside(path, root) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def _has_contrib_component(path, root, contrib_dirs) -> bool:
    rel = Path(path).resolve().relative_to(Path(root).resolve())
    return any(part in contrib_dirs for part in rel.parts[:-1])


def _dir_suffix_matches(dir_abs, suffix: str) -> bool:
    """True if *suffix* (e.g. ``"x"`` from an ``#include "x/X.h"``) names the
    trailing path components of *dir_abs*, or is empty."""
    if not suffix:
        return True
    parts = tuple(suffix.split("/"))
    dparts = Path(dir_abs).parts
    return len(dparts) >= len(parts) and dparts[-len(parts):] == parts


# ---------------------------------------------------------------------------
# cpp-cleanup pass: compilation database
# ---------------------------------------------------------------------------

class CompileDB:
    """Per-file include search paths extracted from a compile_commands.json."""

    def __init__(self, root, per_file, aggregate):
        self.root = root                 # repo root (Path) used for bucketing
        self._per_file = per_file        # {abs source file: [(kind, abs dir)]}
        self._aggregate = aggregate      # union of dirs, for files not listed
        # (headers are never translation units)

    # -- discovery ------------------------------------------------------
    @classmethod
    def discover(cls, search_start):
        path = cls._auto_locate(search_start)
        if path is None:
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _warn(f"cannot read {path}: {exc}")
            return None
        return cls._from_entries(data, path)

    @staticmethod
    def _auto_locate(search_start):
        for base in search_start:
            d = Path(base).resolve()
            if d.is_file():
                d = d.parent
            for cur in (d, *d.parents):
                for cand in (cur / "compile_commands.json",
                             cur / "build" / "compile_commands.json"):
                    if cand.is_file():
                        return cand
                if (cur / ".git").exists():
                    break  # do not escape the repository
        return None

    @classmethod
    def _from_entries(cls, data, db_path):
        root = _find_repo_root(str(db_path.parent)) or db_path.parent
        per_file = {}
        aggregate = []
        seen = set()
        for entry in data:
            directory = entry.get("directory", str(db_path.parent))
            if "arguments" in entry:
                tokens = list(entry["arguments"])
            else:
                tokens = shlex.split(entry.get("command", ""))
            dirs = _extract_include_dirs(tokens, directory)
            file_abs = _norm(os.path.join(directory, entry.get("file", "")))
            per_file[file_abs] = dirs
            for kd in dirs:
                if kd not in seen:
                    seen.add(kd)
                    aggregate.append(kd)
        return cls(root, per_file, aggregate)

    # -- resolution -----------------------------------------------------
    def _dirs_for(self, file_abs):
        # Source files carry their own -I set; headers (never a TU) and
        # unbuilt files fall back to the project-wide union.
        return self._per_file.get(file_abs, self._aggregate)

    def resolve(self, includer_abs, name, is_angle):
        """Return the absolute path *name* resolves to, or None."""
        entry_dirs = self._dirs_for(includer_abs)
        search = []
        if not is_angle:
            search.append(os.path.dirname(includer_abs))
            search += [d for k, d in entry_dirs if k == "iquote"]
        search += [d for k, d in entry_dirs if k == "I"]
        search += [d for k, d in entry_dirs if k == "isystem"]
        search += [d for k, d in entry_dirs if k == "idirafter"]
        for d in search:
            cand = _norm(os.path.join(d, name))
            if os.path.isfile(cand):
                return cand
        return None


def _extract_include_dirs(tokens, directory):
    """Pull (kind, abs-dir) include paths out of a compile command."""
    flags = {"-I": "I", "-iquote": "iquote", "-isystem": "isystem",
             "-idirafter": "idirafter"}
    dirs = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in flags:
            if i + 1 < len(tokens):
                dirs.append((flags[tok], _norm(os.path.join(directory,
                                                            tokens[i + 1]))))
                i += 1
        elif tok.startswith("-I") and len(tok) > 2:
            dirs.append(("I", _norm(os.path.join(directory, tok[2:]))))
        i += 1
    return dirs


# ---------------------------------------------------------------------------
# cpp-cleanup pass: classification
# ---------------------------------------------------------------------------

def classify(target, includer_abs, cfg):
    """Return the group (1-5) for an ``#include`` *target*.

    *target* keeps its delimiters: ``"foo.h"`` or ``<foo.h>``.
    """
    is_angle = target[0] == "<"
    name = target[1:-1].strip()
    db = cfg.db
    resolved = db.resolve(includer_abs, name, is_angle) if db else None

    # 1. associated header: foo.h for foo.c, with or without a path prefix
    # (e.g. x/foo_test.c including "x/foo.h") as long as the prefix names the
    # includer's own directory.  foo_test.c additionally treats foo.h (its
    # subject under test, with the "_test" suffix stripped) as associated,
    # alongside foo_test.h itself.
    if not is_angle and includer_abs.endswith(_C_SOURCE_EXTS):
        stem = os.path.splitext(os.path.basename(includer_abs))[0]
        candidates = [stem]
        if stem.endswith("_test"):
            candidates.append(stem[:-len("_test")])
        inc_dir, base = os.path.split(name)
        includer_dir = os.path.dirname(includer_abs)
        if base in (c + ".h" for c in candidates) and (
                os.path.dirname(resolved) == includer_dir if resolved is not None
                else _dir_suffix_matches(includer_dir, inc_dir)):
            return GROUP_ASSOCIATED

    # 2/3. first-party: resolves somewhere inside the repository
    if resolved is not None and cfg.root is not None \
            and _is_inside(resolved, cfg.root):
        if _has_contrib_component(resolved, cfg.root, cfg.contrib_dirs):
            return GROUP_CONTRIB
        return GROUP_PROJECT

    # 4/5. angle brackets: recognized C/POSIX headers -> 5; anything else
    # (platform / installed third-party) -> 4.
    if is_angle:
        return GROUP_STANDARD if _is_standard(name) else GROUP_PLATFORM

    # quoted but not resolved in-repo (typically: no database) -> heuristics
    if any(part in cfg.contrib_dirs for part in name.split("/")[:-1]):
        return GROUP_CONTRIB
    return GROUP_PROJECT


# ---------------------------------------------------------------------------
# cpp-cleanup pass: preprocessor line recognition
# ---------------------------------------------------------------------------

_INC_RE = re.compile(r'#\s*include\s+(<[^>]+>|"[^"]+")')
_COND_RE = re.compile(r'#\s*(ifndef|ifdef|if|elif|else|endif)\b')


def _is_include(stripped: str) -> bool:
    return _INC_RE.match(stripped) is not None


def _cond_kind(stripped: str):
    m = _COND_RE.match(stripped)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# cpp-cleanup pass: include-block reordering
# ---------------------------------------------------------------------------

def _scan_conditional(lines, i):
    """Scan a conditional starting at opener line *i* to its matching ``#endif``.

    Returns ``(endif_index, has_include, has_code)``.  *has_code* is True if the
    block contains any line that is not blank, a comment, or a preprocessor
    directive -- i.e. real C code (a function/definition), which means the block
    is not part of the include list and must not be reordered.  *endif_index* is
    None if the conditional is unbalanced.
    """
    depth = 0
    has_include = has_code = False
    for j in range(i, len(lines)):
        s = lines[j].strip()
        kind = _cond_kind(s)
        if kind in ("if", "ifdef", "ifndef"):
            depth += 1
        elif kind == "endif":
            depth -= 1
            if depth == 0:
                return j, has_include, has_code
        elif _is_include(s):
            has_include = True
        elif s == "" or s.startswith(("#", "/*", "*", "//")):
            pass  # branch directive (#elif/#else), #define, comment, blank
        else:
            has_code = True
    return None, has_include, has_code


def _find_include_range(lines):
    """Return (start, end) covering the leading ``#include`` region.

    The range runs from the first ``#include`` across contiguous includes, blank
    lines, and any ``#if`` ... ``#endif`` conditional that *only* selects
    includes (no C code).  A conditional carrying real code (e.g. a debug-only
    static function) ends the range and stays in the body.  (None, None) if
    there are no includes.
    """
    start = None
    for i, line in enumerate(lines):
        if _is_include(line.strip()):
            start = i
            break
    if start is None:
        return None, None

    i = start
    end = start
    while i < len(lines):
        s = lines[i].strip()
        kind = _cond_kind(s)
        if _is_include(s):
            i += 1
            end = i
        elif s == "":
            i += 1
        elif kind in ("if", "ifdef", "ifndef"):
            close, has_inc, has_code = _scan_conditional(lines, i)
            if close is None or not has_inc or has_code:
                break
            i = close + 1
            end = i
        else:
            break
    return start, end


def _parse_include_items(lines, start, end, includer_abs, cfg):
    items = []
    for i in range(start, end):
        s = lines[i].strip()
        m = _INC_RE.match(s)
        if m:
            items.append({
                "kind": "include",
                "group": classify(m.group(1), includer_abs, cfg),
                "text": lines[i],
                "sort_key": m.group(0),
            })
        elif s == "":
            items.append({"kind": "blank", "group": None, "text": lines[i]})
        elif s.startswith("#"):
            items.append({"kind": "pp", "group": None, "text": lines[i]})
        else:
            items.append({"kind": "comment", "group": None, "text": lines[i]})
    return items


def _merge_conditional_blocks(items):
    """Coalesce ``#if`` ... ``#endif`` spans into single ``cond_block`` items.

    A block's group and sort key come from its first contained ``#include``.
    """
    stack = []
    result = []
    for item in items:
        if item["kind"] != "pp":
            (stack[-1] if stack else result).append(item)
            continue
        kind = _cond_kind(item["text"].strip())
        if kind in ("if", "ifdef", "ifndef"):
            stack.append([item])
        elif kind == "endif":
            if stack:
                children = stack.pop()
                children.append(item)
                if stack:
                    stack[-1].extend(children)
                else:
                    grp, sort_key = GROUP_STANDARD, ""
                    for c in children:
                        if c["kind"] == "include":
                            grp, sort_key = c["group"], c["sort_key"]
                            break
                    result.append({"kind": "cond_block", "group": grp,
                                   "children": children, "sort_key": sort_key})
            else:
                result.append(item)
        else:  # elif / else / other directive inside a block
            (stack[-1] if stack else result).append(item)
    while stack:  # unbalanced (should not happen) -> flush verbatim
        result.extend(stack.pop())
    return result


def _rebuild_include_block(items):
    items = _merge_conditional_blocks(items)
    groups = {g: [] for g in range(1, NUM_GROUPS + 1)}
    for item in items:
        g = item.get("group")
        if g in groups:
            groups[g].append(item)
    for g in groups:
        groups[g].sort(key=lambda x: x.get("sort_key", "").lower())

    out = []
    first = True
    for g in range(1, NUM_GROUPS + 1):
        if not groups[g]:
            continue
        if not first:
            out.append("\n")
        first = False
        for item in groups[g]:
            if item["kind"] == "cond_block":
                out.extend(c["text"] for c in item["children"])
            else:
                out.append(item["text"])

    cleaned = []
    prev_blank = False
    for line in out:
        blank = line.strip() == ""
        if blank and prev_blank:
            continue
        cleaned.append(line)
        prev_blank = blank
    return cleaned


def _reorder_includes(lines, includer_abs, cfg):
    """Return *lines* with the leading include block regrouped and sorted."""
    start, end = _find_include_range(lines)
    if start is None:
        return lines
    items = _parse_include_items(lines, start, end, includer_abs, cfg)
    if not items:
        return lines

    new_block = _rebuild_include_block(items)
    while new_block and new_block[-1].strip() == "":
        new_block.pop()

    result = list(lines[:start])
    result.extend(new_block)
    result.append("\n")
    body = end
    while body < len(lines) and lines[body].strip() == "":
        body += 1
    result.extend(lines[body:])
    return result


# ---------------------------------------------------------------------------
# cpp-cleanup pass: conditional annotation (/* COND */)
# ---------------------------------------------------------------------------

def _block_comment_mask(lines):
    """Mark lines that *begin* inside a ``/* ... */`` block comment."""
    mask = [False] * len(lines)
    in_comment = False
    for i, s in enumerate(lines):
        mask[i] = in_comment
        j = 0
        while j < len(s):
            if not in_comment:
                if s.startswith("//", j):
                    break
                if s.startswith("/*", j):
                    in_comment = True
                    j += 2
                    continue
                j += 1
            else:
                k = s.find("*/", j)
                if k == -1:
                    break
                in_comment = False
                j = k + 2
    return mask


def _strip_trailing_comment(s):
    s = re.sub(r'/\*.*?\*/\s*$', '', s)
    s = re.sub(r'//.*$', '', s)
    return s.rstrip()


def _condition_text(stripped, kind):
    """Derive the ``/* COND */`` text from an ``#if`` / ``#ifdef`` opener.

    The condition is taken verbatim (an ``#ifndef``/``#ifdef`` yields just the
    macro name); no attempt is made to abbreviate compound expressions, which
    keeps annotations unambiguous.
    """
    s = _strip_trailing_comment(stripped)
    if kind in ("ifndef", "ifdef"):
        m = re.match(r'#\s*\w+\s+(\w+)', s)
        return m.group(1) if m else ""
    m = re.match(r'#\s*\w+\s+(.*)$', s)  # #if <expr>
    return m.group(1).strip() if m else ""


def _has_trailing_comment(stripped):
    return bool(re.search(r'/\*.*\*/\s*$', stripped) or "//" in stripped)


def _append_annotation(line, cond):
    if not cond:
        return line
    newline = ""
    body = line
    if body.endswith("\n"):
        newline, body = "\n", body[:-1]
    return f"{body.rstrip()} /* {cond} */{newline}"


def annotate_conditionals(lines, min_lines):
    """Annotate the ``#endif`` of long or nesting conditionals.

    Add-only: directives that already carry a trailing comment are untouched.
    A construct qualifies when it spans ``min_lines`` or more lines (opener to
    ``#endif``) or nests another conditional.  ``#elif``/``#else`` are left
    bare: ``#elif``'s own condition is already on the line, and ``#else`` has
    no condition of its own to state.

    Only conditions that are a single macro name (``#ifdef``/``#ifndef``, or
    ``#if MACRO``) are annotated; compound expressions are left alone because a
    faithful, readable short form needs human judgment.
    """
    masked = _block_comment_mask(lines)
    stack = []
    annotations = {}

    for i, line in enumerate(lines):
        if masked[i]:
            continue
        s = line.strip()
        kind = _cond_kind(s)
        if kind in ("if", "ifdef", "ifndef"):
            if stack:
                stack[-1]["nested"] = True
            stack.append({"open": i, "cond": _condition_text(s, kind),
                          "nested": False})
        elif kind == "endif":
            if not stack:
                continue
            frame = stack.pop()
            if (i - frame["open"] + 1) < min_lines and not frame["nested"]:
                continue
            cond = frame["cond"]
            if not re.fullmatch(r'[A-Za-z_]\w*', cond):
                continue  # compound condition -> leave to human judgment
            # #endif has no condition of its own -> take the opener's.
            if not _has_trailing_comment(s):
                annotations[i] = cond

    if not annotations:
        return lines
    out = list(lines)
    for idx, cond in annotations.items():
        out[idx] = _append_annotation(out[idx], cond)
    return out


# ---------------------------------------------------------------------------
# cpp-cleanup pass: include-dependency lints (no recursive directories;
# internal/ visibility)
# ---------------------------------------------------------------------------

def _collect_includes(lines):
    out = []
    for i, line in enumerate(lines):
        m = _INC_RE.match(line.strip())
        if m:
            out.append((m.group(1), i + 1))
    return out


def _resolve_in_repo(includer_abs, target, cfg):
    """Resolve ``#include`` *target*; return (resolved_abs, rel, name) if it
    lands inside the repo (*rel* relative to cfg.root), else None."""
    db = cfg.db
    if db is None or cfg.root is None:
        return None
    is_angle = target[0] == "<"
    name = target[1:-1].strip()
    resolved = db.resolve(includer_abs, name, is_angle)
    if not resolved or not _is_inside(resolved, cfg.root):
        return None
    rel = Path(resolved).resolve().relative_to(Path(cfg.root).resolve())
    return resolved, str(rel), name


def _include_dependency(includer_abs, target, cfg):
    res = _resolve_in_repo(includer_abs, target, cfg)
    if res is None:
        return None
    resolved, rel, name = res
    fdir = Path(os.path.dirname(includer_abs)).resolve()
    hdir = Path(os.path.dirname(resolved)).resolve()
    if hdir == fdir:
        return None
    return fdir, hdir, name, rel


def _collect_include_dependency_graph(root, cfg):
    """Return a file-level graph {includer_rel: {header_rel, ...}}.  Kept
    per-file, not collapsed to directories: files sharing a directory must
    not inherit each other's dependencies during the cycle search below."""
    graph = {}
    root_path = cfg.root
    for path in iter_c_files(root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines(
                keepends=True)
        except (OSError, UnicodeError):
            continue
        if path.stem.endswith("_test"):
            continue
        includer_abs = _norm(str(path))
        includer_rel = str(path.resolve().relative_to(root_path))
        for target, _ in _collect_includes(lines):
            res = _resolve_in_repo(includer_abs, target, cfg)
            if res is None:
                continue
            _, header_rel, _ = res
            if header_rel == includer_rel:
                continue
            graph.setdefault(includer_rel, set()).add(header_rel)
    return graph


def _find_dependency_path(graph, start, target_dir):
    """BFS from file *start* to the nearest file under directory
    *target_dir* (both root-relative).  Returns the file-node path, or None."""
    from collections import deque
    queue = deque([start])
    predecessor = {start: None}
    while queue:
        cur = queue.popleft()
        if str(Path(cur).parent) == target_dir:
            path = []
            n = cur
            while n is not None:
                path.append(n)
                n = predecessor[n]
            path.reverse()
            return path
        for neighbor in graph.get(cur, ()):
            if neighbor not in predecessor:
                predecessor[neighbor] = cur
                queue.append(neighbor)
    return None


def check_include_dependencies(includer_abs, includes, cfg):
    """Warn when an include participates in a directory dependency cycle."""
    warnings = []
    graph = cfg.include_dep_graph
    root_path = cfg.root
    includer_rel = str(Path(includer_abs).resolve().relative_to(root_path))
    for target, lineno in includes:
        dep = _include_dependency(includer_abs, target, cfg)
        if dep is None:
            continue
        fdir, _, name, rel = dep
        fdir_rel = str(fdir.relative_to(root_path))
        dep_path = _find_dependency_path(graph, rel, fdir_rel)
        if dep_path is not None:
            steps = [f"{includer_rel} -> {rel}"]
            steps.extend(
                f"{dep_path[i]} -> {dep_path[i + 1]}"
                for i in range(len(dep_path) - 1)
            )
            warnings.append((lineno, name, rel, steps))
    return warnings


def _internal_boundary(hdir, root):
    """Return the allowed root directory for header directory *hdir*, if it
    lies under an ``internal/`` directory (Go's convention: only sources
    inside the tree rooted at internal's parent may include it); else None.

    *hdir* and *root* must both be resolved, absolute paths.  The innermost
    (last) ``internal`` path component sets the boundary.
    """
    parts = hdir.relative_to(root).parts
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] == _INTERNAL_DIR:
            return Path(root, *parts[:i])
    return None


def check_internal_boundary(includer_abs, includes, cfg):
    """Warn when a header under an ``internal/`` directory (Go's convention)
    is included from outside the tree rooted at its parent.

    Headers inside an in-tree contrib/third-party directory are exempt --
    that directory structure is not ours to enforce.
    """
    warnings = []
    root = Path(cfg.root).resolve()
    for target, lineno in includes:
        dep = _include_dependency(includer_abs, target, cfg)
        if dep is None:
            continue
        fdir, hdir, name, rel = dep
        hdir_parts = hdir.relative_to(root).parts
        if any(part in cfg.contrib_dirs for part in hdir_parts):
            continue
        boundary = _internal_boundary(hdir, root)
        if boundary is None or _is_inside(fdir, boundary):
            continue
        warnings.append((lineno, name, rel, str(boundary.relative_to(root))))
    return warnings


# ---------------------------------------------------------------------------
# cpp-cleanup pass: driver
# ---------------------------------------------------------------------------

def _build_cpp_cleanup_config(root: Path):
    cfg = types.SimpleNamespace(contrib_dirs=_DEFAULT_CONTRIB_DIRS, db=None,
                                include_dep_graph={}, root=None)
    db = CompileDB.discover([root])
    if db is not None:
        cfg.db = db
        cfg.root = db.root
    if cfg.root is None:
        cfg.root = _find_repo_root(root) or root
    cfg.include_dep_graph = _collect_include_dependency_graph(root, cfg)
    return cfg


def _cpp_cleanup_text(
        text: str, includer_abs: str, cfg) -> tuple[str, list, list]:
    """Regroup includes and annotate conditionals in *text*.

    Returns ``(new_text, dep_warnings, internal_warnings)``, the two being the
    include-dependency-cycle and internal/-visibility lint hits respectively.
    Pure: it neither reads nor writes files.
    """
    lines = text.splitlines(keepends=True)
    new_lines = _reorder_includes(lines, includer_abs, cfg)
    new_lines = annotate_conditionals(new_lines, _COND_MIN_LINES)
    includes = _collect_includes(lines)
    dep_warnings = check_include_dependencies(includer_abs, includes, cfg)
    internal_warnings = check_internal_boundary(includer_abs, includes, cfg)
    return "".join(new_lines), dep_warnings, internal_warnings


# ---------------------------------------------------------------------------
# Unicode normalization pass
# ---------------------------------------------------------------------------

def _normalize_unicode_bytes(data: bytes, form: str) -> bytes:
    """Return *data* normalized to Unicode *form* (NFC/NFKC)."""
    return unicodedata.normalize(form, data.decode("utf-8")).encode("utf-8")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument(
        "--check", action="store_true",
        help="check for formatting changes without writing them; "
             "exit with status 1 if any file would change",
    )
    parser.add_argument(
        "--nfkc", action="store_true",
        help="use NFKC instead of NFC for Unicode normalization",
    )
    parser.add_argument(
        "--clang-version", default="22.1.5",
        help="required exact clang-format version (default: 22.1.5)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    form = "NFKC" if args.nfkc else "NFC"

    have_clang = _clang_version_ok(args.clang_version)

    # Each file is visited once.  A single original copy is read for change
    # detection and to seed the passes that apply to it (clang-format reads the
    # file itself, so a C source is read at most twice); the file is written
    # back at most once, only if a pass changed it.  C sources under src/ take
    # the clang-format + cpp-cleanup passes; every git-tracked text file takes
    # the Unicode-normalization pass; a file in both sets takes all three but
    # is still handled once.
    cpp_cleanup_cfg = _build_cpp_cleanup_config(root)
    c_by_key = {_norm(str(p)): p for p in iter_c_files(root)}
    text_by_key = {_norm(str(p)): p for p in iter_text_files(root)}
    c_total = len(c_by_key)
    text_total = len(text_by_key)

    clang_changed = clang_lines = 0
    cpp_cleanup_changed = cpp_cleanup_warned = 0
    norm_changed = norm_lines = 0
    changed_files = []

    for key in sorted(set(c_by_key) | set(text_by_key)):
        is_c = key in c_by_key
        path = c_by_key[key] if is_c else text_by_key[key]
        try:
            original = path.read_bytes()
        except OSError as exc:
            _warn(f"skip {path}: {exc}")
            continue

        issue = _utf8_nobom_issue(original)
        if issue is not None:
            _warn(f"skip {path.relative_to(root)}: {issue} "
                  f"(expected UTF-8, no BOM)")
            continue
        data = original

        if is_c and have_clang:
            formatted = _clang_format_file(path, root)
            if formatted != data:
                clang_changed += 1
                clang_lines += formatted.count(b"\n")
            data = formatted

        if is_c:
            pre = data.decode("utf-8")
            new_text, dep_warnings, internal_warnings = _cpp_cleanup_text(
                pre, key, cpp_cleanup_cfg)
            if new_text != pre:
                cpp_cleanup_changed += 1
            data = new_text.encode("utf-8")
            rel = path.relative_to(root)
            if not path.stem.endswith("_test"):
                for lineno, name, target, steps in dep_warnings:
                    cpp_cleanup_warned += 1
                    _warn(f"{rel}:{lineno}: recursive directory dependency "
                          f"through header \"{name}\" ({target})")
                    for step in steps:
                        print(f"  cycle: {step}", file=sys.stderr)
            for lineno, name, target, boundary in internal_warnings:
                cpp_cleanup_warned += 1
                _warn(f"{rel}:{lineno}: internal header \"{name}\" "
                      f"({target}) not visible outside {boundary}/")

        if key in text_by_key:
            normalized = _normalize_unicode_bytes(data, form)
            if normalized != data:
                norm_changed += 1
                norm_lines += normalized.count(b"\n")
            data = normalized

        if data != original:
            if args.check:
                changed_files.append(path.relative_to(root))
            else:
                path.write_bytes(data)

    if have_clang:
        print(f"clang-format: {clang_lines} lines in "
              f"{clang_changed}/{c_total} files changed")
    print(f"cpp-cleanup: {cpp_cleanup_changed}/{c_total} files changed, "
          f"{cpp_cleanup_warned} warning(s)")
    print(f"normalize {form}: {norm_lines} lines in "
          f"{norm_changed}/{text_total} files changed")

    if args.check:
        for rel in changed_files:
            print(f"would reformat {rel}")
        if changed_files:
            print(f"format --check: {len(changed_files)} file(s) "
                  f"would be reformatted")
            sys.exit(1)
        print("format --check: no changes needed")


if __name__ == "__main__":
    main()
