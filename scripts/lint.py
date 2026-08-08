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
  scripts/lint.py --raw-list PATH            # also write a diffable raw findings list

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
import shlex
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
# Prune the compilation database to one command per source
# ---------------------------------------------------------------------------

def _entry_args(entry: dict) -> list[str]:
    """Return an entry's compiler arguments, in whichever of the two forms
    the compilation database used."""
    args = entry.get("arguments")
    if args is not None:
        return list(args)
    return shlex.split(entry.get("command", ""))


def _prune_db(build_dir: Path, sources: list[str]) -> Path:
    """Write a compilation database holding exactly one command per accepted
    source and return the directory containing it.

    CMake emits one command per (source, target) pair, so a source linked
    into several test targets appears once per target -- when this was
    written, 222 commands for 140 files, up to 7 for one source.  clang-tidy
    analyzes a named source once for *every* matching command, so those
    repeats re-run the whole check set on identical code: the surplus
    commands differ only in the output object path and in -D macros that
    configure other modules.  Keeping one command per source cuts the run by
    an order of magnitude and leaves the report unchanged.
    """
    db_path = build_dir / "compile_commands.json"
    if not db_path.exists():
        sys.exit(f"error: {db_path} not found — run cmake first")
    db: list[dict] = json.loads(db_path.read_text(encoding="utf-8"))
    wanted = set(sources)
    best: dict[str, tuple[int, dict]] = {}
    for entry in db:
        fpath = entry["file"]
        if fpath not in wanted:
            continue
        # Of the commands for one source, keep the richest configuration --
        # the one carrying the most -D/-I flags.  It compiles the most
        # conditional code, so dropping the others cannot hide a region that
        # only a target-specific macro enables.  Ties keep the first command
        # in database order, so the choice is deterministic.
        rank = sum(a.startswith(("-D", "-I")) for a in _entry_args(entry))
        chosen = best.get(fpath)
        if chosen is None or rank > chosen[0]:
            best[fpath] = (rank, entry)
    out_dir = build_dir / "tmp" / "lint-db"
    out_dir.mkdir(parents=True, exist_ok=True)
    pruned = [best[src][1] for src in sources if src in best]
    (out_dir / "compile_commands.json").write_text(
        json.dumps(pruned, indent=1), encoding="utf-8")
    return out_dir


# ---------------------------------------------------------------------------
# Run clang-tidy
# ---------------------------------------------------------------------------

def _tidy_one(
    base: list[str], src: str
) -> tuple[str, int | None, str, str]:
    """Run clang-tidy on a single accepted source and return
    (src, returncode, stdout, stderr).  returncode is None if the binary is
    missing.  stderr is captured rather than discarded: on success it is only
    per-file progress noise and is dropped by the caller, but on failure it
    carries the one diagnostic that says what went wrong."""
    try:
        proc = subprocess.run(
            base + [src],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,  # returncode is inspected by the caller
        )
    except FileNotFoundError:
        return src, None, "", ""
    return src, proc.returncode, proc.stdout, proc.stderr


# How much of a failing clang-tidy's stderr to quote: enough for a rejected
# -checks glob or a malformed compile command, and the tail of a crash
# backtrace, without pasting a whole dump into the exit message.
_STDERR_TAIL_LINES = 20


def _stderr_tail(text: str) -> str:
    """Return the last few non-empty lines of *text* for an exit message."""
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "no diagnostic"
    tail = lines[-_STDERR_TAIL_LINES:]
    if len(lines) > _STDERR_TAIL_LINES:
        dropped = len(lines) - _STDERR_TAIL_LINES
        tail.insert(0, f"... ({dropped} earlier lines)")
    return "\n".join(tail)


def _run(
    db_dir: Path, check_filter: str | None, jobs: int, sources: list[str]
) -> str:
    # Drive clang-tidy directly, one process per accepted production source,
    # fanned out across `jobs` workers. We invoke clang-tidy itself rather than
    # the run-clang-tidy wrapper so the only tool this needs is clang-tidy;
    # clang-tidy walks the compile database for each named source and analyzes
    # it for every compile command, and we concatenate the per-file diagnostics
    # (emitted on stdout) for the parser below. `db_dir` is the pruned database
    # from _prune_db, which holds one command per source so no file is analyzed
    # twice. Passing the accepted sources explicitly keeps the analysis to
    # production files, rather than the whole database whose test/generated
    # results would just be discarded during post-filtering, wasting the
    # analysis and inflating the reported elapsed time.
    base = ["clang-tidy", "-p", str(db_dir)]
    if check_filter:
        base += [f"-checks=-*,{check_filter}"]
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        results = list(pool.map(lambda src: _tidy_one(base, src), sources))
    outputs: list[str] = []
    for src, code, out, err in results:
        if code is None:
            sys.exit(
                "error: clang-tidy not found — install the llvm tools package")
        # A non-zero status means clang-tidy errored on that source: a malformed
        # compile command, an internal crash, a rejected -checks glob, or an
        # error-level diagnostic. Its stdout is then partial, so treating it as
        # "no warnings" would report a broken run as a clean tree; fail loudly,
        # quoting the captured stderr that says what actually went wrong -- the
        # file name alone forces a manual re-run to learn the cause.
        if code != 0:
            sys.exit(
                f"error: clang-tidy exited with status {code} on {src}; "
                "lint results are unreliable (a tool failure is not a clean "
                f"run)\n{_stderr_tail(err)}")
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

        # Drop findings outside the repo. A project source always resolves to a
        # repo-relative path (via name_map), so a still-absolute path here is a
        # system/third-party header — e.g. <netdb.h> flagged because a test mock
        # redeclares a libc function. Those are never actionable by the cleanup
        # skill, which only edits in-repo sources.
        if os.path.isabs(relpath):
            continue

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
# strings/uctype.h repeats the pattern one layer up: it is the char32_t/UTF-8
# counterpart to ctype_ascii.h and, in the WITH_ICU build, claims the very same
# <ctype.h> names as macros over uctype_* functions. It carries the same
# mutual-exclusion #error, so a file including it cannot also include <ctype.h>
# — yet include-cleaner still demands <ctype.h> for every isdigit/tolower/...
#
# The same failure recurs for several standard/third-party headers whose symbol
# supply clang's map misattributes or overlooks: <sys/wait.h> (wait-status
# macros clang credits to <stdlib.h>), <errno.h>, <netinet/in.h> and <net/if.h>
# (whose symbols clang can miss), <syslog.h> (a one-line wrapper around glibc's
# <sys/syslog.h>, which is where the decls physically live and where clang
# points), the POSIX types ssize_t/socklen_t (a real provider header is
# included, yet clang reports none), and libraries that expose a prefixed symbol
# family through public headers that are not where the decls end up: libsodium
# (<sodium.h>) and Lua (<lua.h>) funnel theirs through one umbrella, while ICU
# rewrites every C symbol through <unicode/urename.h> (u_tolower ->
# u_tolower_77), so the visible decl never sits in the documented
# <unicode/*.h>. Each surfaces as one of two misc-include-cleaner phrasings: the
# symbol reads as unprovided ("no header providing ..."), or the header reads as
# unused ("included header ... is not used directly").
#
# The denoiser withholds only findings it can PROVE are such false positives;
# it must never drop a finding that could be a real defect. Every rule is a
# _Provider entry anchored to concrete evidence in the source: a finding is
# suppressed only when the file actually includes the provider header AND the
# flagged symbol genuinely belongs to that provider (an exact name, a name
# parsed out of one of our own replacement headers, or a library symbol-prefix).
# A missing include unrelated to a known provider (pid_t, char32_t, ...) is left
# untouched, as is a header whose symbols overlap other headers (e.g.
# <sys/types.h> reported unused — possibly a genuine redundant include — is
# never suppressed) and a name this project itself also defines (LOG_PERROR is
# both a <syslog.h> option and a utils/slog.h macro, so it is excluded from the
# <syslog.h> rule). Suppressed findings are still reported in their own section,
# and --no-denoise disables the pass, so nothing is silently hidden.
# ---------------------------------------------------------------------------

# Include roots under which our own headers' spellings ("utils/ctype_ascii.h",
# "strings/uctype.h") resolve on disk, mirroring the build's -I paths. In
# csnippets itself they live under src/; the downstream projects vendor
# csnippets under contrib/csnippets/, so the same include spelling resolves
# there instead. Searched in order; the first hit wins (only one root exists in
# any given tree). Without this the denoiser silently no-ops in the vendored
# trees and every such finding leaks into the report as if it were a real defect.
_HEADER_INCLUDE_ROOTS = ("src", "contrib/csnippets")

# misc-include-cleaner phrasing for a used-but-not-directly-included symbol.
_INCLUDE_CLEANER_MISSING_RE = re.compile(
    r'^no header providing "(?P<sym>[^"]+)" is directly included$'
)

# misc-include-cleaner phrasing for an included-but-directly-unused header.
_INCLUDE_CLEANER_UNUSED_RE = re.compile(
    r"^included header (?P<hdr>\S+) is not used directly$"
)

def _basename_include_re(basename: str) -> re.Pattern:
    """Compile a regex matching an `#include` of any path ending in `basename`.

    `basename` is a regex fragment for the file name alone, e.g. r'uctype\\.h'.
    It matches every spelling of our own headers — #include "strings/uctype.h",
    the bare "uctype.h" used from within strings/, the vendored
    "csnippets/strings/uctype.h", or any <...> form. Anchoring on the basename
    keeps the rule correct regardless of the include-path prefix a project
    spells it with, while the leading "/"-or-start requirement rejects unrelated
    names like "myuctype.h".
    """
    return re.compile(
        r'^[ \t]*#[ \t]*include[ \t]*[<"](?:[^">]*/)?' + basename + r'[">]',
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
    # glibc's <syslog.h> is a one-line wrapper that includes <sys/syslog.h>,
    # where openlog()/syslog() and the LOG_* constants physically live. Without
    # an IWYU export pragma clang credits the inner header and reports the
    # POSIX-mandated <syslog.h> as providing nothing. The set is POSIX.1-2008's
    # complete <syslog.h> surface (facilities, priorities, options, the mask
    # macros and the four functions) minus LOG_PERROR: utils/slog.h defines a
    # macro of that name too, so a file missing *that* include must keep its
    # finding. The set is exact rather than a LOG_ prefix for the same reason —
    # slog.h's own LOG_LEVEL_*/LOG_F names share the prefix.
    _Provider(
        name="<syslog.h>",
        include=_include_re(r"syslog\.h"),
        unused_basename="syslog.h",
        symbols=frozenset({
            "openlog", "syslog", "closelog", "setlogmask", "vsyslog",
            "LOG_KERN", "LOG_USER", "LOG_MAIL", "LOG_NEWS", "LOG_UUCP",
            "LOG_DAEMON", "LOG_AUTH", "LOG_CRON", "LOG_LPR", "LOG_SYSLOG",
            "LOG_AUTHPRIV", "LOG_FTP", "LOG_LOCAL0", "LOG_LOCAL1",
            "LOG_LOCAL2", "LOG_LOCAL3", "LOG_LOCAL4", "LOG_LOCAL5",
            "LOG_LOCAL6", "LOG_LOCAL7",
            "LOG_EMERG", "LOG_ALERT", "LOG_CRIT", "LOG_ERR", "LOG_WARNING",
            "LOG_NOTICE", "LOG_INFO", "LOG_DEBUG",
            "LOG_PID", "LOG_CONS", "LOG_NDELAY", "LOG_ODELAY", "LOG_NOWAIT",
            "LOG_MASK", "LOG_UPTO", "LOG_PRI", "LOG_MAKEPRI", "LOG_FAC",
        }),
        prefixes=None,
        note="declared in <sys/syslog.h>, which <syslog.h> wraps",
    ),
    # ICU rewrites every C symbol through <unicode/urename.h> — u_tolower
    # becomes u_tolower_77 — so the decl clang sees never sits in the documented
    # <unicode/uchar.h>, <unicode/unorm2.h>, ... that callers must include. Any
    # <unicode/*.h> include proves the file is an ICU translation unit; the
    # prefixes are ICU's own C-module naming (u_* core, plus the modules this
    # tree uses), and the types are listed exactly because a bare "U" prefix
    # would swallow unrelated names such as UINT8_C. Extending either as more
    # ICU modules come into use is the fail-safe direction: an unlisted symbol
    # keeps its finding rather than losing it. unused_basename is None because
    # an ICU header that really is redundant (a leftover <unicode/utypes.h>) is
    # a genuine cleanup worth reporting.
    _Provider(
        name="<unicode/*.h>",
        include=_include_re(r"unicode/\w+\.h"),
        unused_basename=None,
        symbols=frozenset({
            "UChar", "UChar32", "UBool", "UErrorCode", "UNormalizer2",
            "UDateFormat", "UDateFormatStyle", "UCharCategory", "UProperty",
            "UVersionInfo",
        }),
        prefixes=("u_", "unorm2_", "udat_"),
        note="ICU symbol renamed through <unicode/urename.h>",
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


def _header_provided_names(root: Path, spelling: str) -> set[str]:
    """Names the header at `spelling` provides (macros and inline functions).

    Parsed from the header itself so the set stays correct as the header evolves.
    The header is looked up under each known include root (src/ for csnippets,
    contrib/csnippets/ for the downstream projects that vendor it). Returns an
    empty set if it cannot be read under any root — that header's rule then
    simply never fires (fail safe: keep every finding).
    """
    text: str | None = None
    for inc_root in _HEADER_INCLUDE_ROOTS:
        try:
            text = (root / inc_root / spelling).read_text(encoding="utf-8")
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


# This project's own <ctype.h> replacements: headers that deliberately claim the
# standard classification names (isdigit, tolower, ...) as macros, so a file
# including one cannot include <ctype.h> — which is exactly what include-cleaner
# demands. Both #error out if <ctype.h>'s macros are already defined, so the
# claim is exclusive and the rule cannot mask a genuine missing <ctype.h>.
# Fields: (include spelling on disk, basename regex, unused-header basename,
# reason note). Provided names are parsed from each header at run time.
_OWN_CTYPE_HEADERS: tuple[tuple[str, str, str, str], ...] = (
    ("utils/ctype_ascii.h", r"ctype_ascii\.h", "ctype_ascii.h",
     "ASCII-only <ctype.h> replacement"),
    ("strings/uctype.h", r"uctype\.h", "uctype.h",
     "char32_t/Unicode <ctype.h> replacement"),
)


def _providers(root: Path) -> list[_Provider]:
    """The provider table for `root`: the static entries plus this project's own
    <ctype.h> replacements, whose provided-name sets are parsed from the
    (possibly vendored) headers. An entry is omitted when its header cannot be
    read, so its rule simply never fires there (fail safe)."""
    providers = list(_STATIC_PROVIDERS)
    for spelling, basename, unused_basename, note in _OWN_CTYPE_HEADERS:
        names = _header_provided_names(root, spelling)
        if not names:
            continue
        providers.append(_Provider(
            name=spelling,
            include=_basename_include_re(basename),
            unused_basename=unused_basename,
            symbols=frozenset(names),
            prefixes=None,
            note=note,
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


def _finding_id(w: dict) -> str:
    """Stable identity of a finding for the raw list: check, file and message,
    but NOT the line number — so an unrelated edit that shifts lines never
    churns the list (and its diff)."""
    return f"{w['check']}\t{w['file']}\t{w['msg']}"


_RAW_LIST_HEADER = """\
# clang-tidy raw findings list — regenerated by `scripts/lint.py --raw-list`.
#
# One actionable finding per line, tab-separated, sorted:
#     <check>\t<file>\t<message>
# Line numbers are omitted on purpose so unrelated edits do not churn the diff.
# Committed so a later run can `git diff` it: added lines are newly-introduced
# findings to triage, removed lines are findings that were resolved.
#
# Which findings appear at all depends on the build configuration named below:
# the path-sensitive analyzer checks explore different paths at different
# optimization levels, and NDEBUG turns ASSERT() into a no-op, removing
# constraints they prune with. Diff two lists only if this line matches.
#
# Machine-generated — do not hand-edit.
"""


def _write_raw_list(path: Path, warnings: list[dict], config: str) -> None:
    """Write `path` with the identities of the current actionable findings,
    sorted for a stable diff."""
    ids = sorted({_finding_id(w) for w in warnings})
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(ids)
    path.write_text(
        _RAW_LIST_HEADER + f"# Build configuration: {config}\n"
        + (body + "\n" if body else ""), encoding="utf-8")


def _build_config(build_dir: Path) -> str:
    """Describe the configuration in *build_dir*, for the report header.

    The findings depend on it -- the path-sensitive clang-analyzer checks
    explore different paths at different optimization levels, and NDEBUG turns
    ASSERT() into a no-op, removing constraints they prune with.  A findings
    list is therefore only comparable against one taken the same way, so say
    which way that was rather than leaving it to be guessed.
    """
    cache = build_dir / "CMakeCache.txt"
    wanted = {
        "CMAKE_BUILD_TYPE": "build",
        "CMAKE_C_COMPILER": "compiler",
        "ENABLE_SANITIZERS": "sanitizers",
    }
    found: dict[str, str] = {}
    try:
        for line in cache.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if not sep:
                continue
            name = key.split(":", 1)[0]
            if name in wanted:
                found[wanted[name]] = value.strip()
    except OSError:
        return "unknown (no CMakeCache.txt)"
    if "compiler" in found:
        found["compiler"] = Path(found["compiler"]).name
    parts = [f"{k}={v}" for k, v in found.items() if v]
    return ", ".join(parts) if parts else "unknown"


def _report(
    warnings: list[dict], suppressed: list[dict], check_filter: str | None,
    elapsed: float, excluded: list[str], config: str,
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
        f"> Build configuration: {config} &mdash; findings are only "
        "comparable against a list taken under the same one",
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

    # Organise by file; within a file the findings are sorted by line so the
    # report reads top-to-bottom like the source, each row naming its check.
    by_file: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
    for w in warnings:
        by_file[w["file"]].append((w["line"], w["check"], w["msg"]))

    # --- Summary: files, most findings first ---
    out += ["## Summary", "", "| File | Warnings |", "|---|---:|"]
    for f in sorted(by_file, key=lambda k: (-len(by_file[k]), k)):
        out.append(f"| `{f}` | {len(by_file[f])} |")
    out.append("")

    # --- Findings: one section per file, findings in line order ---
    out += ["## Findings", ""]
    for fpath in sorted(by_file):
        entries = sorted(by_file[fpath])
        n = len(entries)
        noun = "warning" if n == 1 else "warnings"
        out.append(f"### **`{fpath}`** — {n} {noun}")
        out.append("")
        out += ["| Line | Check | Message |", "|---:|---|---|"]
        for line_no, check, msg in entries:
            safe = msg.replace("|", "\\|").replace("`", "\\`")
            out.append(f"| {line_no} | `{check}` | {safe} |")
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
    ap.add_argument(
        "--raw-list",
        metavar="PATH",
        help="also write a raw, line-number-free findings list to PATH (in "
        "addition to the Markdown report); commit it so a later run can `git "
        "diff` it to see which findings are newly introduced.  Record the "
        "build configuration printed alongside it: a list is only comparable "
        "against one taken under the same configuration",
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

    lint_db = _prune_db(build_dir, sources)
    print(f"Linting [{check_label}] ...", file=sys.stderr, flush=True)
    t0 = time.monotonic()
    raw = _run(lint_db, args.check, args.jobs, sources)
    elapsed = time.monotonic() - t0

    warnings = _parse(raw, name_map, accept)
    if args.no_denoise:
        kept, suppressed = warnings, []
    else:
        kept, suppressed = _denoise(warnings, ROOT)

    config = _build_config(build_dir)
    print(
        f"{len(kept)} warning(s)"
        f"{f', {len(suppressed)} suppressed' if suppressed else ''}"
        f" in {elapsed:.1f} s → {out_path}",
        file=sys.stderr,
    )
    # the configuration decides which findings appear at all, so name it here
    # too: a list is only comparable against one taken the same way
    print(f"  linted {build_dir} [{config}]", file=sys.stderr)

    md = _report(
        kept, suppressed, args.check, elapsed,
        _excluded_labels(args.tests, args.generated), config,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")

    if args.raw_list:
        raw_path = Path(args.raw_list)
        _write_raw_list(raw_path, kept, config)
        print(
            f"{len({_finding_id(w) for w in kept})} finding(s) → {raw_path}"
            f" [{config}]",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
