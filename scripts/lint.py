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
facilities (the archetype is misc-include-cleaner on utils/ctype_ascii.h, an
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
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
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
    clang-tidy so only production sources are analyzed."""
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

def _tidy_one(
    base: list[str], src: str
) -> tuple[str, int | None, str]:
    """Run clang-tidy on a single accepted source and return
    (src, returncode, stdout).  returncode is None if the binary is missing."""
    try:
        proc = subprocess.run(
            base + [src],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # only the per-file progress noise
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,  # returncode is inspected by the caller
        )
    except FileNotFoundError:
        return src, None, ""
    return src, proc.returncode, proc.stdout


def _run(
    build_dir: Path, check_filter: str | None, jobs: int, sources: list[str]
) -> str:
    # Drive clang-tidy directly, one process per accepted production source,
    # fanned out across `jobs` workers. We invoke clang-tidy itself rather than
    # the run-clang-tidy wrapper so the only tool this needs is clang-tidy;
    # clang-tidy walks the compile database for each named source and analyzes
    # it for every compile command, and we concatenate the per-file diagnostics
    # (emitted on stdout) for the parser below. Passing the accepted sources
    # explicitly keeps the analysis to production files, rather than the whole
    # database whose test/generated results would just be discarded during
    # post-filtering, wasting the analysis and inflating the reported elapsed
    # time.
    base = ["clang-tidy", "-p", str(build_dir)]
    if check_filter:
        base += [f"-checks=-*,{check_filter}"]
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        results = list(pool.map(lambda src: _tidy_one(base, src), sources))
    outputs: list[str] = []
    for src, code, out in results:
        if code is None:
            sys.exit(
                "error: clang-tidy not found — install the llvm tools package")
        # A non-zero status means clang-tidy errored on that source: a malformed
        # compile command, an internal crash, a rejected -checks glob, or an
        # error-level diagnostic. Its stdout is then partial, so treating it as
        # "no warnings" would report a broken run as a clean tree; fail loudly.
        if code != 0:
            sys.exit(
                f"error: clang-tidy exited with status {code} on {src}; "
                "lint results are unreliable (a tool failure is not a clean run)")
        outputs.append(out)
    return "".join(outputs)


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
        # clang-tidy repeats a header's warnings once per translation
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
# Some checks are valuable in general but fire false positives when a header
# genuinely provides a symbol yet clang-tidy's include-cleaner fails to credit
# it. The archetype is misc-include-cleaner and utils/ctype_ascii.h, which
# defines the character-classification family (isdigit, isalnum, isprint,
# tolower, ...) as ASCII-only macros that deliberately replace <ctype.h> — the
# two are mutually exclusive, ctype_ascii.h #errors if ctype.h's macros are
# already defined.
# include-cleaner maps those names to <ctype.h> unconditionally and reports "no
# header providing isdigit", a demand that is impossible to satisfy here.
#
# The same failure recurs for several standard/third-party headers whose symbol
# supply clang's map misattributes or overlooks: <sys/wait.h> (wait-status
# macros clang credits to <stdlib.h>), <errno.h>, <netinet/in.h> and <net/if.h>
# (whose symbols clang can miss), the POSIX types ssize_t/socklen_t (a real
# provider header is included, yet clang reports none), and single-umbrella
# libraries such as libsodium (<sodium.h>) and Lua (<lua.h>) that expose an
# entire prefixed symbol family through one public header. Each surfaces as one
# of two misc-include-cleaner phrasings: the symbol reads as unprovided ("no
# header providing ..."), or the header reads as unused ("included header ... is
# not used directly").
#
# The denoiser withholds only findings it can PROVE are such false positives;
# it must never drop a finding that could be a real defect. Every rule is a
# _Provider entry anchored to concrete evidence in the source: a finding is
# suppressed only when the file actually includes the provider header AND the
# flagged symbol genuinely belongs to that provider (an exact name, a
# ctype_ascii.h-defined name, or a library symbol-prefix). A missing include unrelated
# to a known provider (pid_t, char32_t, openlog, ...) is left untouched, as is a
# header whose symbols overlap other headers (e.g. <sys/types.h> reported unused
# — possibly a genuine redundant include — is never suppressed). Suppressed
# findings are still reported in their own section, and --no-denoise disables the
# pass, so nothing is silently hidden.
# ---------------------------------------------------------------------------

ASCII_HEADER = "utils/ctype_ascii.h"  # spelling used in #include directives

# Include roots under which the "utils/ctype_ascii.h" spelling resolves on
# disk, mirroring the build's -I paths. In csnippets itself the header lives
# under src/; the downstream projects vendor csnippets under contrib/csnippets/,
# so the same include spelling resolves there instead. Searched in order; the
# first hit wins (only one root exists in any given tree). Without this the
# denoiser silently no-ops in the vendored trees and every ctype_ascii.h finding
# leaks into the report as if it were a real defect.
_HEADER_INCLUDE_ROOTS = ("src", "contrib/csnippets")

# misc-include-cleaner phrasing for a used-but-not-directly-included symbol.
_INCLUDE_CLEANER_MISSING_RE = re.compile(
    r'^no header providing "(?P<sym>[^"]+)" is directly included$'
)

# misc-include-cleaner phrasing for an included-but-directly-unused header.
_INCLUDE_CLEANER_UNUSED_RE = re.compile(
    r"^included header (?P<hdr>\S+) is not used directly$"
)

# An #include whose target basename is ctype_ascii.h — e.g.
# #include "utils/ctype_ascii.h", the bare "ctype_ascii.h" spelling used from
# within strings/, the vendored "csnippets/utils/ctype_ascii.h", or any <...>
# form. Anchoring on the basename keeps the rule correct regardless of the
# include-path prefix a project spells it with, while the leading "/"-or-start
# requirement rejects unrelated names like "myctype_ascii.h".
_ASCII_INCLUDE_RE = re.compile(
    r'^[ \t]*#[ \t]*include[ \t]*[<"](?:[^">]*/)?ctype_ascii\.h[">]',
    re.MULTILINE,
)


def _include_re(spelling: str) -> re.Pattern:
    """Compile a regex matching a `#include` of `spelling` (angle or quote form).

    `spelling` is a regex fragment for the header path, e.g. r'sys/wait\\.h' or
    r'(?:lua|lauxlib)\\.h'. It is matched verbatim (no basename relaxation), so
    a bare <wait.h> is not mistaken for <sys/wait.h>.
    """
    return re.compile(
        r'^[ \t]*#[ \t]*include[ \t]*[<"]' + spelling + r'[">]', re.MULTILINE)


# A provider is a header that genuinely supplies a family of symbols whose
# supply clang-tidy fails to credit. Fields:
#   name             reason-text label, e.g. "<sys/wait.h>"
#   include          _include_re() matching the header's #include directive
#   unused_basename  basename as reported in "included header X not used
#                    directly" (drives the "unused header" rule); None disables
#                    that rule for this provider — used when the header's symbols
#                    overlap other headers, so "unused" may be a real finding
#   symbols          exact provided names (frozenset), or None
#   prefixes         provided-symbol name prefixes for umbrella libraries
#                    (tuple), or None
#   note             short parenthetical appended to the suppression reason
_Provider = namedtuple(
    "_Provider", "name include unused_basename symbols prefixes note")

_STATIC_PROVIDERS: tuple[_Provider, ...] = (
    # POSIX.1-2008 mandates <sys/wait.h> for the wait-status macros and
    # waitpid()/waitid(); glibc's <stdlib.h> only optionally (XSI) re-exposes
    # them and clang's symbol map credits <stdlib.h>, never <sys/wait.h>.
    _Provider(
        name="<sys/wait.h>",
        include=_include_re(r"sys/wait\.h"),
        unused_basename="wait.h",
        symbols=frozenset({
            "WIFEXITED", "WEXITSTATUS", "WIFSIGNALED", "WTERMSIG", "WIFSTOPPED",
            "WSTOPSIG", "WIFCONTINUED", "WCOREDUMP", "WNOHANG", "WUNTRACED",
            "WCONTINUED", "waitpid", "waitid",
        }),
        prefixes=None,
        note="POSIX wait-status symbol clang maps to <stdlib.h>",
    ),
    # `errno` is a macro (*__errno_location()); clang can miss macro-only use
    # and report <errno.h> unused even where errno is read.
    _Provider(
        name="<errno.h>",
        include=_include_re(r"errno\.h"),
        unused_basename="errno.h",
        symbols=frozenset({"errno"}),
        prefixes=None,
        note="clang can miss macro-only <errno.h> use",
    ),
    # The socket-address structures and IP protocol/address constants are
    # declared only in <netinet/in.h>; clang misattributes them.
    _Provider(
        name="<netinet/in.h>",
        include=_include_re(r"netinet/in\.h"),
        unused_basename="in.h",
        symbols=frozenset({
            "sockaddr_in", "sockaddr_in6", "in_addr", "in6_addr", "in_port_t",
            "in_addr_t", "ip_mreq", "ipv6_mreq", "ip_mreqn",
        }),
        prefixes=("IPPROTO_", "INADDR_", "IN6ADDR_"),
        note="declared only in <netinet/in.h>",
    ),
    # Interface-name helpers and IFNAMSIZ are declared only in <net/if.h>.
    _Provider(
        name="<net/if.h>",
        include=_include_re(r"net/if\.h"),
        unused_basename="if.h",
        symbols=frozenset({
            "IFNAMSIZ", "if_nametoindex", "if_indextoname", "if_nameindex",
            "if_freenameindex", "ifreq", "ifconf",
        }),
        prefixes=None,
        note="declared only in <net/if.h>",
    ),
    # ssize_t is provided by <unistd.h> and <sys/types.h>; clang can report "no
    # header providing ssize_t" even where one is included. Two entries so the
    # rule fires whichever provider the file actually includes. Neither drives
    # the "unused header" rule (unused_basename=None): <sys/types.h> in
    # particular is a frequent redundant include, and suppressing its "unused"
    # finding could hide a real cleanup.
    _Provider(
        name="<unistd.h>",
        include=_include_re(r"unistd\.h"),
        unused_basename=None,
        symbols=frozenset({"ssize_t"}),
        prefixes=None,
        note="POSIX type provided by an included header clang overlooks",
    ),
    _Provider(
        name="<sys/types.h>",
        include=_include_re(r"sys/types\.h"),
        unused_basename=None,
        symbols=frozenset({"ssize_t"}),
        prefixes=None,
        note="POSIX type provided by an included header clang overlooks",
    ),
    # socklen_t is provided by <sys/socket.h>; clang can report it unprovided.
    _Provider(
        name="<sys/socket.h>",
        include=_include_re(r"sys/socket\.h"),
        unused_basename=None,
        symbols=frozenset({"socklen_t"}),
        prefixes=None,
        note="POSIX type provided by <sys/socket.h> clang overlooks",
    ),
    # libsodium exposes its whole API — crypto_*, sodium_*, randombytes_* — only
    # through the umbrella <sodium.h>; include-cleaner wants a per-symbol header
    # that does not exist for callers.
    _Provider(
        name="<sodium.h>",
        include=_include_re(r"sodium\.h"),
        unused_basename="sodium.h",
        symbols=None,
        prefixes=("crypto_", "sodium_", "randombytes_"),
        note="libsodium umbrella header",
    ),
    # Lua's LUA_* configuration constants come from <luaconf.h>, pulled in by the
    # public <lua.h>/<lauxlib.h>; clang reports them unprovided.
    _Provider(
        name="<lua.h>",
        include=_include_re(r"(?:lua|lauxlib)\.h"),
        unused_basename=None,
        symbols=None,
        prefixes=("LUA_",),
        note="Lua constant from <luaconf.h> via <lua.h>",
    ),
)


def _provider_provides(p: _Provider, sym: str) -> bool:
    """True if provider `p` genuinely supplies `sym` (exact name or prefix)."""
    if p.symbols is not None and sym in p.symbols:
        return True
    if p.prefixes is not None and sym.startswith(p.prefixes):
        return True
    return False


def _provider_use_re(p: _Provider) -> re.Pattern | None:
    """Regex matching any in-source use of a symbol `p` provides, or None.

    Used as the evidence that an "unused header" finding is a false positive:
    the header only looks unused because clang credited one of these uses to a
    different header. The search runs over `_strip_noncode()`-cleaned source so
    a symbol name that appears only in a comment, a string literal, or the
    provider's own `#include` line is not mistaken for a genuine use.
    """
    parts: list[str] = []
    if p.symbols:
        parts.append(
            r"\b(?:" + "|".join(re.escape(s) for s in sorted(p.symbols))
            + r")\b")
    if p.prefixes:
        parts.append(
            r"\b(?:" + "|".join(re.escape(x) for x in p.prefixes) + r")\w+\b")
    return re.compile("|".join(parts)) if parts else None


# Regions of C source whose text can spell a provider symbol's name without
# being a genuine use of it: comments (`/* clears errno */`), string/char
# literals (`"errno was set"`), and `#include` directives (whose header name
# `<errno.h>` contains the word `errno`). The "unused header" rule's use-search
# must rest on real code, so these are blanked before the search runs —
# otherwise a redundant `#include` whose symbol appears only in such text would
# be wrongly proven "used" and its genuine finding suppressed, breaking the
# denoiser's provable-false-positive contract.
_NONCODE_RE = re.compile(
    r"""
      //[^\n]*                          # line comment
    | /\*.*?\*/                         # block comment
    | "(?:\\.|[^"\\\n])*"               # string literal
    | '(?:\\.|[^'\\\n])*'               # char literal
    | ^[ \t]*\#[ \t]*include\b[^\n]*    # #include directive (header filename)
    """,
    re.VERBOSE | re.DOTALL | re.MULTILINE,
)


def _strip_noncode(src: str) -> str:
    """Blank comments, string/char literals and `#include` lines out of `src`.

    Each such region is replaced by spaces of equal length (newlines kept), so
    the result is the same source with only genuine code tokens left for the
    symbol-use search. Preserving length matters: it keeps adjacent tokens
    separated (`err/*x*/no` stays `err     no`, never collapses to `errno`).
    """
    return _NONCODE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), src)


def _ascii_provided_names(root: Path) -> set[str]:
    """Names that utils/ctype_ascii.h provides (macros and inline functions).

    Parsed from the header itself so the set stays correct as the header evolves.
    The header is looked up under each known include root (src/ for csnippets,
    contrib/csnippets/ for the downstream projects that vendor it). Returns an
    empty set if it cannot be read under any root — the ctype_ascii.h rule then
    simply never fires (fail safe: keep every finding).
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


def _providers(root: Path) -> list[_Provider]:
    """The provider table for `root`: the static entries plus
    utils/ctype_ascii.h, whose provided-name set is parsed from the (possibly
    vendored) header. The ctype_ascii.h entry is omitted when the header cannot
    be read, so its rule simply never fires there (fail safe)."""
    providers = list(_STATIC_PROVIDERS)
    ascii_names = _ascii_provided_names(root)
    if ascii_names:
        providers.append(_Provider(
            name=ASCII_HEADER,
            include=_ASCII_INCLUDE_RE,
            unused_basename="ctype_ascii.h",
            symbols=frozenset(ascii_names),
            prefixes=None,
            note="ASCII-only <ctype.h> replacement",
        ))
    return providers


def _denoise(
    warnings: list[dict], root: Path
) -> tuple[list[dict], list[dict]]:
    """Split warnings into (kept, suppressed).

    A warning is suppressed only when a provider rule can prove it is a false
    positive — the file includes the provider header AND the flagged symbol
    genuinely belongs to it; suppressed warnings carry a human-readable
    'reason'. Everything else — including anything uncertain — is kept.
    """
    providers = _providers(root)
    use_res: dict[str, re.Pattern | None] = {
        p.name: _provider_use_re(p) for p in providers
    }
    src_cache: dict[str, str | None] = {}
    code_cache: dict[str, str | None] = {}

    def file_src(relpath: str) -> str | None:
        if relpath not in src_cache:
            try:
                src_cache[relpath] = (
                    root / relpath).read_text(encoding="utf-8")
            except OSError:
                src_cache[relpath] = None
        return src_cache[relpath]

    def code_src(relpath: str) -> str | None:
        """`file_src` with comments, literals and #include lines blanked out —
        the genuine-code view the "unused header" use-search must rest on."""
        if relpath not in code_cache:
            raw = file_src(relpath)
            code_cache[relpath] = (
                _strip_noncode(raw) if raw is not None else None)
        return code_cache[relpath]

    def includes(relpath: str, pattern: re.Pattern) -> bool:
        src = file_src(relpath)
        return src is not None and bool(pattern.search(src))

    def noise_reason(w: dict) -> str | None:
        if w["check"] != "misc-include-cleaner":
            return None

        # "no header providing <sym>": suppress when some provider that genuinely
        # supplies <sym> is directly included by the file.
        m = _INCLUDE_CLEANER_MISSING_RE.match(w["msg"])
        if m is not None:
            sym = m.group("sym")
            for p in providers:
                if (_provider_provides(p, sym)
                        and includes(w["file"], p.include)):
                    return f"`{p.name}` provides `{sym}` ({p.note})"
            return None

        # "included header <hdr> not used directly": suppress when a provider
        # with that basename is included AND the file actually uses one of its
        # symbols in code — so the header only looks unused because clang
        # credited the use elsewhere. The use-search runs over code_src (comments,
        # literals and #include lines blanked) so a symbol named only in a
        # comment/string, or in the provider's own #include line, is not counted.
        u = _INCLUDE_CLEANER_UNUSED_RE.match(w["msg"])
        if u is not None:
            base = Path(u.group("hdr")).name
            for p in providers:
                if p.unused_basename != base:
                    continue
                use_re = use_res[p.name]
                if use_re is None or not includes(w["file"], p.include):
                    continue
                src = code_src(w["file"])
                hit = use_re.search(src) if src is not None else None
                if hit is not None:
                    return (
                        f"`{p.name}` is used via `{hit.group(0)}`, which clang "
                        f"misattributes ({p.note})"
                    )
            return None
        return None

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
        "from this project's own facilities (e.g. `utils/ctype_ascii.h`). These are "
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
        help="keep known false positives (e.g. the utils/ctype_ascii.h "
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
        # clang-tidy analyze the entire database, so stop here instead.
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
