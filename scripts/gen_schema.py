#!/usr/bin/env python3
# csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
# This code is licensed under MIT license (see LICENSE for details)
"""scripts/gen_schema.py

Generate C code from JSON Schema files: perfect-hash key dispatchers,
struct definitions, and marshal/unmarshal/free functions that use the
codec/json.h API.

Usage:
    python3 scripts/gen_schema.py [OPTIONS] <schema.json> ...

Options:
    --generate FEATURES  Comma-separated list of features to generate:
                           structs    — struct type definitions + free functions
                           unmarshal  — lookup tables (always internal) +
                                        unmarshal functions
                           marshal    — marshal functions
                           lookup     — expose the enum and lookup function
                                        in the generated header (unmarshal
                                        generates them internally regardless)
                         Default: structs,unmarshal,marshal.
                         Dependency rules:
                           unmarshal/marshal each imply structs; lookup does
                           not (it emits only the key enums and lookup
                           functions).
                           lookup tables are always generated internally for
                           unmarshal; lookup only controls whether the enum
                           and lookup function are made public.
                         Free functions are always generated with structs.
    --prefix S           Prepend S to every public generated symbol:
                         struct types, function names, enum names,
                         lookup functions, and enum-value prefixes.
                         Joined with a single '_' whether or not S ends in
                         one: "ex" and "ex_" both give struct ex_<stem>,
                         ex_unmarshal_<stem>, EX_<STEM>_<KEY>.
    --optimize MODE      Selects the code-generation backend and key-lookup
                         strategy together.
                         fast (default): bespoke per-scope unmarshal/marshal
                           functions + gperf perfect-hash lookup.  Fastest
                           runtime; largest object code; needs gperf.
                         size: compact descriptor tables interpreted by the
                           generic runtime in json.h + memcmp binary-search
                           lookup.  Object code shrinks dramatically (the
                           per-scope logic lives once in the runtime) at the
                           cost of ~6-18% slower (un)marshal; no gperf needed.
                         Keys are emitted as quoted literals, so gperf
                         handles almost arbitrary bytes; an empty key, or
                         a key containing '?' (both of which gperf cannot
                         take), falls back to binary search.
                         NOTE: 'size' requires the generic runtime
                         (json_unmarshal/json_marshal/json_free) in codec/json.
    --strict             Reject unknown keys in unmarshal
                         (additionalProperties: false semantics).
    --no-validate        Omit schema-constraint validation from unmarshal.
    --sub-schema         Also make the free/unmarshal/marshal functions of
                         nested sub-schemas public (by default only the
                         root object's are; nested helpers are static).
    --include-prefix P   Include project headers as "P/json.h" rather than
                         "json.h" (default: codec).
    --output-name BASE   Name the generated files BASE.gen.{h,c} instead of
                         after the schema stem (sanitized to a C identifier).
                         Generated symbols still derive from the schema stem.
    --indent STYLE       Indentation of the generated C code: 'tab'
                         (default) for one tab per level, or an integer N
                         for N spaces per level.

Semantics notes:
    * unmarshal: duplicate keys follow last-value-wins; on failure *obj is
      reset to all-zero with partial allocations released.
    * marshal: snprintf semantics (returns required length excluding NUL,
      NUL-terminates whenever bufsz > 0); returns -1 for non-finite doubles.
      The trailing `indent` argument selects pretty output: a per-level
      indentation string (e.g. "  " or "\t"), or NULL for compact output.
    * minLength/maxLength compare UTF-8 byte lengths, not code points.
    * $ref, union types, and other unsupported constructs degrade to raw
      JSON fragment fields; a warning is printed for each.

Output per input schema (<stem> is the schema basename, or --output-name):
    <dir>/<stem>.gen.h   -- declarations (enums, lookups, structs, protos)
    <dir>/<stem>.gen.c   -- implementations (lookups, free, unmarshal, marshal)

Examples:
    # generate all (default)
    python3 scripts/gen_schema.py src/mux/proto_schema.json

    # structs + unmarshal only, with a prefix to avoid name conflicts
    python3 scripts/gen_schema.py --generate structs,unmarshal --prefix json_ \\
        src/conf_schema.json

    # full codec generation with prefix
    python3 scripts/gen_schema.py --prefix json_ src/conf_schema.json
"""

import argparse
import json
import math
import re
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

_INT32_MIN = -(2**31)
_INT32_MAX = 2**31 - 1
_UINT32_MAX = 2**32 - 1
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_UINT64_MAX = 2**64 - 1


def _c_u64_literal(value: int) -> str:
    """Return a portable C literal for an unsigned 64-bit value."""
    return f"UINT64_C({value})"

# Inclusive value range of each inferred C field type, used to drop a bound
# comparison that is always true/false for the type (e.g. `x < INT_MIN`), which
# would otherwise trip -Wtype-limits under -Werror. Unknown types get an
# unbounded range so every check is kept.
_C_TYPE_RANGE = {
    "int": (_INT32_MIN, _INT32_MAX),
    "unsigned": (0, _UINT32_MAX),
    "intmax_t": (_INT64_MIN, _INT64_MAX),
    "uintmax_t": (0, _UINT64_MAX),
}

# The complete --generate feature set; anything else on that option is a typo.
_FEATURES = frozenset({"structs", "unmarshal", "marshal", "lookup"})

# One indentation level for generated C source (default tab; set by --indent).
_INDENT = "\t"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def to_c_ident(s: str) -> str:
    """Return *s* sanitized into a valid, non-reserved C identifier."""
    # Collapse each maximal run of non-identifier bytes to a single '_'.  '_' is
    # excluded from the retained class, so a literal '_' beside a separator (or a
    # run of separators) folds in rather than forming an internal '__', which
    # the generated names never contain -- a house rule kept stricter than
    # ISO C11 §7.1.3, which reserves only a *leading* '__' (C++ [lex.name]
    # reserves one anywhere); a lone '_' is a run of one and is kept.
    ident = re.sub(r"[^A-Za-z0-9]+", "_", s)
    # A name that does not start with a letter needs repairing, and the repair
    # must not be an underscore: ISO C11 §7.1.3 reserves every identifier
    # beginning with one for file scope -- where the schema prefix seeds the
    # struct/enum tags and functions -- and reserves '_' + uppercase for any
    # use.  A leading letter keeps the result out of both namespaces.  The same
    # substitution can leave
    # a leading '_' without any digit involved ('.env' -> '_env'), so key off
    # "not a letter", not "digit".  The empty string is a legal JSON key and
    # maps to "x"; _make_field_map still resolves any collision that creates
    # (e.g. with a key like ",") by appending a numeric suffix.
    if not ident or not ident[0].isalpha():
        ident = "x" + ident
    return ident


# ISO C11 language keywords (§6.4.1) and underscore-capital keywords (§7.1.3).
# These may never appear as identifiers.
_C11_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while",
    "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic",
    "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local",
})

# The keywords GCC and Clang add outside the reserved namespace in their GNU
# modes (-std=gnu*, which is what a plain `cc` compiles with); -std=c11 still
# accepts them as identifiers, so a name that compiles there fails to parse
# for a consumer who does not pass it.
_GNU_KEYWORDS = frozenset({
    "asm", "typeof",
})

# <stdbool.h> — Boolean type and values (C11 §7.18).
# bool/true/false are object-like macros; using them as identifiers triggers
# macro expansion and produces a syntax error.
_STDBOOL_NAMES = frozenset({
    "bool", "true", "false",
})

# <stddef.h> — Common definitions (C11 §7.19).
# NULL is an object-like macro; offsetof is function-like but still reserved.
_STDDEF_NAMES = frozenset({
    "ptrdiff_t", "size_t", "max_align_t", "wchar_t",
    "NULL", "offsetof",
})

# <stdint.h> — Integer types with specified widths (C11 §7.20).
_STDINT_NAMES = frozenset({
    # Exact-width (optional; universally present on POSIX targets)
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    # Minimum-width (required)
    "int_least8_t", "int_least16_t", "int_least32_t", "int_least64_t",
    "uint_least8_t", "uint_least16_t", "uint_least32_t", "uint_least64_t",
    # Fastest minimum-width (required)
    "int_fast8_t", "int_fast16_t", "int_fast32_t", "int_fast64_t",
    "uint_fast8_t", "uint_fast16_t", "uint_fast32_t", "uint_fast64_t",
    # Pointer-width (optional; universally present on POSIX targets)
    "intptr_t", "uintptr_t",
    # Maximum-width (required)
    "intmax_t", "uintmax_t",
})

# <stdio.h> — I/O types (C11 §7.21).
# Included in the generated .c file for snprintf.
_STDIO_NAMES = frozenset({
    "FILE", "fpos_t",
})

# <stdlib.h> — General-utilities types (C11 §7.22).
# Included in the generated .c file for bsearch/free/malloc.
_STDLIB_NAMES = frozenset({
    "div_t", "ldiv_t", "lldiv_t",
})

# <string.h> — String types (C11 §7.24).
# Included in the generated .c file for memcmp; introduces no new type names
# beyond size_t (already in _STDDEF_NAMES).

# POSIX.1-2008 extensions used by the project's codec/json.h API.
_POSIX_NAMES = frozenset({
    "ssize_t",
})

# The object-like macros ISO C defines in the headers the generated files
# include: the header pulls in <stddef.h>, <stdbool.h>, <stdint.h> (directly
# and through codec/json.h), and the .c adds <string.h>, <stdlib.h>,
# <limits.h>, <stdio.h>, <math.h> and <float.h>.  An identifier spelled like
# one of these is macro-expanded wherever it appears -- a struct member, an
# enumerator, a struct tag -- and the generated code no longer parses.
# Function-like macros (INT8_C, isnan, ...) are left out: every generated
# identifier that is followed by '(' carries a lowercase verb, so none can
# spell one.
_STDINT_MACROS = frozenset(
    [f"{pfx}INT{w}_MAX" for pfx in ("", "U") for w in (8, 16, 32, 64)]
    + [f"INT{w}_MIN" for w in (8, 16, 32, 64)]
    + [f"{pfx}INT_{kind}{w}_MAX" for pfx in ("", "U")
       for kind in ("LEAST", "FAST") for w in (8, 16, 32, 64)]
    + [f"INT_{kind}{w}_MIN" for kind in ("LEAST", "FAST")
       for w in (8, 16, 32, 64)]
    + ["INTPTR_MIN", "INTPTR_MAX", "UINTPTR_MAX",
       "INTMAX_MIN", "INTMAX_MAX", "UINTMAX_MAX",
       "PTRDIFF_MIN", "PTRDIFF_MAX", "SIG_ATOMIC_MIN", "SIG_ATOMIC_MAX",
       "SIZE_MAX", "WCHAR_MIN", "WCHAR_MAX", "WINT_MIN", "WINT_MAX"]
)

# <limits.h> — Sizes of integer types (C11 §5.2.4.2.1).
_LIMITS_MACROS = frozenset({
    "CHAR_BIT", "SCHAR_MIN", "SCHAR_MAX", "UCHAR_MAX", "CHAR_MIN", "CHAR_MAX",
    "MB_LEN_MAX", "SHRT_MIN", "SHRT_MAX", "USHRT_MAX", "INT_MIN", "INT_MAX",
    "UINT_MAX", "LONG_MIN", "LONG_MAX", "ULONG_MAX", "LLONG_MIN", "LLONG_MAX",
    "ULLONG_MAX",
})

# <stdio.h> (C11 §7.21.1), <stdlib.h> (§7.22) and <math.h> (§7.12).
_STDIO_MACROS = frozenset({
    "BUFSIZ", "EOF", "FILENAME_MAX", "FOPEN_MAX", "L_tmpnam",
    "SEEK_CUR", "SEEK_END", "SEEK_SET", "TMP_MAX",
    "stderr", "stdin", "stdout",
})
_STDLIB_MACROS = frozenset({
    "EXIT_FAILURE", "EXIT_SUCCESS", "MB_CUR_MAX", "RAND_MAX",
})
_MATH_MACROS = frozenset({
    "HUGE_VAL", "HUGE_VALF", "HUGE_VALL", "INFINITY", "NAN",
    "FP_INFINITE", "FP_NAN", "FP_NORMAL", "FP_SUBNORMAL", "FP_ZERO",
    "FP_FAST_FMA", "FP_FAST_FMAF", "FP_FAST_FMAL", "FP_ILOGB0", "FP_ILOGBNAN",
    "MATH_ERRNO", "MATH_ERREXCEPT", "math_errhandling",
})

# <float.h> — Characteristics of floating types (C11 §5.2.4.2.2); the fast
# backend's .c includes it for DBL_EPSILON.  *_NORM_MAX is C2x, but Clang's
# <float.h> defines it in every GNU mode.
_FLOAT_MACROS = frozenset(
    [f"{t}_{m}" for t in ("FLT", "DBL", "LDBL") for m in (
        "DECIMAL_DIG", "DIG", "EPSILON", "HAS_SUBNORM", "MANT_DIG", "MAX",
        "MAX_10_EXP", "MAX_EXP", "MIN", "MIN_10_EXP", "MIN_EXP", "NORM_MAX",
        "TRUE_MIN")]
    + ["DECIMAL_DIG", "FLT_EVAL_METHOD", "FLT_RADIX", "FLT_ROUNDS"]
)

# The system-name macros GCC and Clang predefine outside the reserved
# namespace in their default GNU modes (-std=gnu*, which is what a plain `cc`
# compiles with); -std=c11 withholds them, so a name that compiles there
# fails for a consumer who does not pass it.
_GNU_PREDEFINED_MACROS = frozenset({
    "i386", "linux", "unix",
})

# The object-like macros the same headers define outside ISO C once a
# feature-test macro is on: POSIX.1-2008 (-D_POSIX_C_SOURCE=200809L, which
# examples/ builds with), X/Open, glibc's _DEFAULT_SOURCE (implied by
# -std=gnu*, the mode the downstream projects compile in) and _GNU_SOURCE
# (which they define on Linux).  Past ISO C the set is platform-dependent;
# this is what glibc exposes to GCC and Clang under -std=gnu11 -D_GNU_SOURCE,
# a superset of every narrower mode, and scripts/gen_schema_test.py checks it
# against the compiler in each of them.
#
# The integer width macros (ISO/IEC TS 18661-1, later C2x) of <stdint.h> and
# <limits.h>.
_WIDTH_MACROS = frozenset(
    [f"{pfx}INT{w}_WIDTH" for pfx in ("", "U") for w in (8, 16, 32, 64)]
    + [f"{pfx}INT_{kind}{w}_WIDTH" for pfx in ("", "U")
       for kind in ("LEAST", "FAST") for w in (8, 16, 32, 64)]
    + [f"{t}_WIDTH" for t in (
        "INTPTR", "UINTPTR", "INTMAX", "UINTMAX", "PTRDIFF", "SIG_ATOMIC",
        "SIZE", "WCHAR", "WINT", "CHAR", "SCHAR", "UCHAR", "SHRT", "USHRT",
        "INT", "UINT", "LONG", "ULONG", "LLONG", "ULLONG", "BOOL")]
    + ["BOOL_MAX"]
)
# <limits.h>: the POSIX/XSI limits, plus GNU's LONG_LONG_* spellings.
_POSIX_LIMITS_MACROS = frozenset({
    "AIO_PRIO_DELTA_MAX", "BC_BASE_MAX", "BC_DIM_MAX", "BC_SCALE_MAX",
    "BC_STRING_MAX", "CHARCLASS_NAME_MAX", "COLL_WEIGHTS_MAX",
    "DELAYTIMER_MAX", "EXPR_NEST_MAX", "HOST_NAME_MAX", "IOV_MAX",
    "LINE_MAX", "LOGIN_NAME_MAX", "LONG_BIT", "MAX_CANON", "MAX_INPUT",
    "MQ_PRIO_MAX", "NAME_MAX", "NGROUPS_MAX", "NL_ARGMAX", "NL_LANGMAX",
    "NL_MSGMAX", "NL_NMAX", "NL_SETMAX", "NL_TEXTMAX", "NZERO", "PATH_MAX",
    "PIPE_BUF", "PTHREAD_DESTRUCTOR_ITERATIONS", "PTHREAD_KEYS_MAX",
    "PTHREAD_STACK_MIN", "RE_DUP_MAX", "RTSIG_MAX", "SEM_VALUE_MAX",
    "SSIZE_MAX", "TTY_NAME_MAX", "WORD_BIT", "XATTR_LIST_MAX",
    "XATTR_NAME_MAX", "XATTR_SIZE_MAX",
    "LONG_LONG_MIN", "LONG_LONG_MAX", "ULONG_LONG_MAX",
})
# <stdio.h>: POSIX's L_ctermid/P_tmpdir, and glibc's L_cuserid, SEEK_DATA/HOLE
# and renameat2 flags.
_POSIX_STDIO_MACROS = frozenset({
    "L_ctermid", "L_cuserid", "P_tmpdir", "SEEK_DATA", "SEEK_HOLE",
    "RENAME_EXCHANGE", "RENAME_NOREPLACE", "RENAME_WHITEOUT",
})
# <stdlib.h>: the <sys/wait.h> flags POSIX has it define, and what glibc's
# <sys/types.h> brings in through it (<endian.h>, <sys/select.h>).
_POSIX_STDLIB_MACROS = frozenset({
    "WCONTINUED", "WEXITED", "WNOHANG", "WNOWAIT", "WSTOPPED", "WUNTRACED",
    "BIG_ENDIAN", "BYTE_ORDER", "LITTLE_ENDIAN", "PDP_ENDIAN",
    "FD_SETSIZE", "NFDBITS",
})
# <math.h>: the XSI constants (M_PI, ...) and their glibc per-type spellings,
# X/Open's MAXFLOAT, and glibc's TS 18661 macros.
_FLOATN = ("F32", "F64", "F128", "F32X", "F64X")
_POSIX_MATH_MACROS = frozenset(
    [c + sfx for c in (
        "M_E", "M_LOG2E", "M_LOG10E", "M_LN2", "M_LN10", "M_PI", "M_PI_2",
        "M_PI_4", "M_1_PI", "M_2_PI", "M_2_SQRTPI", "M_SQRT2", "M_SQRT1_2")
     for sfx in ("", "f", "l", *(n.lower() for n in _FLOATN))]
    + ["HUGE_VAL_" + n for n in _FLOATN]
    + ["SNAN", "SNANF", "SNANL", *("SNAN" + n for n in _FLOATN)]
    + ["MAXFLOAT", "FP_LLOGB0", "FP_LLOGBNAN",
       "FP_INT_DOWNWARD", "FP_INT_TONEAREST", "FP_INT_TONEARESTFROMZERO",
       "FP_INT_TOWARDZERO", "FP_INT_UPWARD"]
)

# The subset of the names above that are only typedef names (see
# _TAG_RESERVED).
_TYPEDEF_NAMES = (
    _STDINT_NAMES | _STDIO_NAMES | _STDLIB_NAMES | _POSIX_NAMES
    | (_STDDEF_NAMES - {"NULL", "offsetof"})
)

# Combined set used by _make_field_map to detect name collisions.
_C_KEYWORDS = (
    _C11_KEYWORDS | _GNU_KEYWORDS | _STDBOOL_NAMES | _STDDEF_NAMES |
    _STDINT_NAMES | _STDIO_NAMES | _STDLIB_NAMES | _POSIX_NAMES |
    _STDINT_MACROS | _LIMITS_MACROS | _STDIO_MACROS | _STDLIB_MACROS |
    _MATH_MACROS | _FLOAT_MACROS | _GNU_PREDEFINED_MACROS |
    _WIDTH_MACROS | _POSIX_LIMITS_MACROS | _POSIX_STDIO_MACROS |
    _POSIX_STDLIB_MACROS | _POSIX_MATH_MACROS
)


def _escape_keyword(ident: str) -> str:
    """Return *ident* made safe to use as a C identifier.

    A name that collides with a C keyword (including GNU mode's ``typeof``), a
    reserved type name, or one of the object-like macros the generated code
    has in scope in ISO, POSIX or GNU mode (``bool``, ``NULL``, ``SIZE_MAX``,
    ``EOF``, ``PATH_MAX``, ``M_PI``, GNU's ``unix``, ...) gets a trailing
    underscore, which is the same rule ``_make_field_map`` applies to property
    names."""
    return ident + "_" if ident in _C_KEYWORDS else ident


def _join_ident(*parts: str) -> str:
    """Join identifier segments with single '_' separators, never doubling.

    Empty segments are dropped.  A separator is inserted between two kept
    segments only where neither side already carries one, so a segment ending
    in '_' -- a keyword-escaped or otherwise underscore-terminated schema stem
    such as ``int_`` (from ``int``) or ``foo_`` (from ``foo-``) -- absorbs the
    separator instead of forming an internal ``__`` (see to_c_ident).  For
    segments that neither end nor begin with '_' -- every scope name, ename and
    lookup name a schema without such a stem produces -- the result is
    byte-identical to ``"_".join(p for p in parts if p)``, so existing output
    is unchanged.
    """
    out = ""
    for p in parts:
        if not p:
            continue
        if out and not out.endswith("_") and not p.startswith("_"):
            out += "_"
        out += p
    return out


def _count_member(fname: str) -> str:
    """Return the name of an array field's element-count companion member."""
    return _join_ident(fname, "count")


def _json_member(fname: str) -> str:
    """Return the member name of a dynamic (raw JSON fragment) field."""
    return _join_ident(fname, "json")


def _derived_member(kind: str, fname: str) -> "str | None":
    """Return the companion struct member a field of *kind* also occupies.

    ``generate_structs_h`` gives an array field a ``<fname>_count`` companion
    and names a dynamic field's member ``<fname>_json``; both share the
    struct's member namespace with the plain field names, so
    ``_make_field_map`` has to reserve them.  Both are joined through
    _join_ident, so a keyword-escaped ``for_`` gets ``for_count``, not
    ``for__count``.  Every other kind occupies its plain name only.
    """
    if _is_array_kind(kind):
        return _count_member(fname)
    if kind == "dynamic":
        return _json_member(fname)
    return None


def _make_field_map(keys: list, node: dict) -> dict:
    """Return a collision-free mapping from JSON property name → C field name.

    Handles four cases in order:
    1. Runs of non-identifier characters collapsed to a single '_'; a name not
       starting with a letter prefixed with 'x' (both via to_c_ident).
    2. C reserved-word conflicts -- a keyword, type name or macro in scope,
       codec/json.h's include guard included: append '_' suffix (e.g. 'int'
       → 'int_').
    3. Duplicate names after steps 1-2: append '_2', '_3', ... (through
       _join_ident, so an escaped 'int_' becomes 'int_2', not 'int__2'),
       sorted by (C identifier, JSON key) so the result is deterministic: all
       colliding keys are grouped together and the alphabetically-first JSON
       key within each collision group keeps the plain name.
    4. The companion member names generate_structs_h derives from a field name
       (see _derived_member) are reserved alongside it, and a name is
       accepted only when its own companion is free too.  Without this a
       schema pairing ``tags`` (array) with a ``tags_count`` property -- or
       ``raw`` (dynamic) with ``raw_json`` -- generates a struct with a
       duplicate member, which the generator accepts and the C compiler then
       rejects with a message naming neither the schema nor the property.
    """
    # Steps 1-2: raw conversion for every key.  Wherever the struct is
    # defined, codec/json.h is included, and its include guard is an empty
    # object-like macro like any other in scope.
    raw = {}
    for key in keys:
        ident = to_c_ident(key)
        raw[key] = ident + "_" if ident in _JSON_H_MACROS \
            else _escape_keyword(ident)

    # Step 4 input: the companion member each key's kind brings along.  A node
    # without usable properties (never produced by collect_scopes, but the map
    # builders take an arbitrary node) simply contributes none.
    props = node.get("properties", {}) if isinstance(node, dict) else {}
    kinds = {}
    for key in keys:
        prop = props.get(key)
        kinds[key] = _infer_c_type(prop)["kind"] \
            if key in props else None

    # Step 3: resolve duplicates.  Sort by (C identifier, JSON key) so that
    # colliding keys are grouped together and the assignment of plain name vs
    # suffix depends only on the C identifier ordering, not on JSON key
    # characters that have no C meaning (e.g. '-' vs '_').
    used: set = set()
    result: dict = {}
    for key in sorted(keys, key=lambda k: (raw[k], k)):
        base = raw[key]
        cand, n = base, 1
        while cand in used or _derived_member(kinds[key], cand) in used:
            n += 1
            cand = _join_ident(base, str(n))
        used.add(cand)
        companion = _derived_member(kinds[key], cand)
        if companion is not None:
            used.add(companion)
        result[key] = cand

    return result


def _make_enum_const_map(keys: list, node: dict, ename: str) -> dict:
    """Return a collision-free mapping JSON key → full enum-constant name.

    An enum constant is ``<ENAME>_<FIELD>`` with both parts uppercased.  The
    C field names are unique only case-sensitively (``_make_field_map``), so
    uppercasing can collapse two of them onto the same token (e.g. keys ``id``
    and ``ID`` → field names ``id`` and ``ID`` → both ``ID``), which would emit
    a duplicate enumerator and duplicate ``switch`` case label.  Disambiguate
    the same way ``_make_field_map`` disambiguates field names: append
    ``_2``, ``_3``, ... (through ``_join_ident``) in a deterministic order.
    Keys with no case collision keep the plain ``<ENAME>_<FIELD>`` name, so
    existing output is unchanged.
    """
    fname_map = _make_field_map(keys, node)
    base = {key: fname_map[key].upper() for key in keys}
    used: set = set()
    result: dict = {}
    for key in sorted(keys, key=lambda k: (base[k], fname_map[k], k)):
        cand = base[key]
        if cand in used:
            n = 2
            while _join_ident(cand, str(n)) in used:
                n += 1
            cand = _join_ident(cand, str(n))
        used.add(cand)
        result[key] = _join_ident(ename.upper(), cand)
    return result


# ---------------------------------------------------------------------------
# Schema traversal
# ---------------------------------------------------------------------------

def _canonicalize(node):
    """Return a canonical copy of a JSON Schema node.

    Equivalent schemas (same content, any property order) are collapsed to a
    unique representation so all downstream code always sees the same input.
    Normalizations applied recursively:

    * ``properties`` dict — keys sorted alphabetically.
    * ``$defs`` / ``definitions`` dict — keys sorted alphabetically.
    * ``required`` array — sorted and deduplicated.
    * All other nested dicts and arrays — recursively canonicalized.
    """
    if isinstance(node, list):
        return [_canonicalize(item) for item in node]
    if not isinstance(node, dict):
        return node
    result = {}
    for k, v in node.items():
        if k == "properties" and isinstance(v, dict):
            result[k] = {pk: _canonicalize(pv) for pk, pv in sorted(v.items())}
        elif k in ("$defs", "definitions") and isinstance(v, dict):
            result[k] = {dk: _canonicalize(dv) for dk, dv in sorted(v.items())}
        elif k == "required" and isinstance(v, list):
            result[k] = sorted(set(v))
        else:
            result[k] = _canonicalize(v)
    return result


# Keywords whose value JSON Schema requires to be a number, and those whose
# value it requires to be a non-negative integer (an integer-valued number such
# as 2.0 included).
_NUMBER_KEYWORDS = frozenset({
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "multipleOf",
})
_COUNT_KEYWORDS = frozenset({
    "minLength", "maxLength", "minItems", "maxItems", "minProperties",
    "maxProperties", "minContains", "maxContains",
})


def _keyword_value_error(key: str, value) -> "str | None":
    """Explain why *value* is not a legal value of the numeric keyword *key*,
    or return None when it is.

    A boolean is refused explicitly: bool is a Python subclass of int, so it
    would otherwise pass as the number 0 or 1 -- and be spelled ``True`` in the
    emitted C.  A non-finite float is refused too: Python's json module accepts
    NaN and Infinity (and an overflowing literal such as 1e400 decodes to
    Infinity), but none of them is a JSON number.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        shown = "" if value is None else f" {json.dumps(value)}"
        return f"must be a number, not the JSON {_json_type_name(value)}{shown}"
    if isinstance(value, float) and not math.isfinite(value):
        return f"must be a finite number, not {value!r}"
    if key in _COUNT_KEYWORDS and (value < 0 or value != math.floor(value)):
        return f"must be a non-negative integer, not {value!r}"
    return None


def _reject_malformed_keywords(node, path="") -> None:
    """Reject, at schema-processing time, a keyword value the JSON Schema
    meta-schema forbids and no generated check could honor: an empty
    ``enum``, a malformed ``required``, and a numeric keyword
    (_NUMBER_KEYWORDS, _COUNT_KEYWORDS) whose value is not a number of the
    kind the keyword takes.

    Every schema node is screened, whether or not the generator enforces the
    keyword there, so both backends refuse exactly the same schemas before
    either reads a bound."""
    if isinstance(node, dict):
        enum = node.get("enum")
        if isinstance(enum, list) and not enum:
            sys.exit(
                f"error: {path or '<root>'}: enum must contain at least "
                "one item (an empty enum is unsatisfiable)")
        if "required" in node:
            required = node["required"]
            if not isinstance(required, list):
                sys.exit(
                    f"error: {path or '<root>'}: required must be an array "
                    f"of property-name strings, not the JSON "
                    f"{_json_type_name(required)}")
            for name in required:
                if not isinstance(name, str):
                    sys.exit(
                        f"error: {path or '<root>'}: required must contain "
                        f"only property-name strings, not the JSON "
                        f"{_json_type_name(name)}")
        for key in sorted(_NUMBER_KEYWORDS | _COUNT_KEYWORDS):
            if key not in node:
                continue
            why = _keyword_value_error(key, node[key])
            if why is not None:
                sys.exit(f"error: {path or '<root>'}: {key} {why}")
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for prop, child in value.items():
                    child_path = f"{path}.{prop}" if path else prop
                    _reject_malformed_keywords(child, child_path)
            elif key == "items":
                _reject_malformed_keywords(value, path + "[]")
            elif key in ("$defs", "definitions", "dependentSchemas") \
                    and isinstance(value, dict):
                # a name -> subschema map: its keys are names, not keywords
                for name, child in value.items():
                    child_path = f"{path}.{name}" if path else name
                    _reject_malformed_keywords(child, child_path)
            elif key in ("allOf", "anyOf", "oneOf", "not", "if", "then",
                         "else", "prefixItems", "contains",
                         "additionalProperties", "propertyNames",
                         "unevaluatedItems", "unevaluatedProperties"):
                _reject_malformed_keywords(value, path)
    elif isinstance(node, list):
        for value in node:
            _reject_malformed_keywords(value, path)


def collect_scopes(node, prefix: str, path: str = "",
                   paths: "dict | None" = None):
    """Yield (scope_name, keys, node) for every JSON object scope with fixed
    properties.  Objects that carry only ``additionalProperties`` (dynamic
    keys, no ``properties``) are skipped — they appear as JSON-fragment
    ``char *`` / ``size_t`` fields in their parent struct instead.

    When *paths* is given, it is filled with scope_name → the dotted JSON
    property path the scope was found at ("" for the root), so a diagnostic
    can name the property rather than the C identifier derived from it.
    """
    if not isinstance(node, dict):
        return
    if node.get("type") == "object" and "properties" in node:
        name = prefix if not path else _join_ident(prefix, to_c_ident(path))
        keys = sorted(node["properties"])
        if keys:
            if paths is not None:
                paths.setdefault(name, path)
            yield name, keys, node
        for prop, child in sorted(node["properties"].items()):
            child_path = f"{path}.{prop}" if path else prop
            yield from collect_scopes(child, prefix, child_path, paths)
    elif node.get("type") == "array":
        # Descend only when the array itself becomes a field of that element
        # type.  An array whose items are not a supported kind -- an
        # array-of-array-of-object, say -- degrades to a raw JSON fragment in
        # _infer_c_type, so no struct field would ever name a scope found
        # beneath it; yielding one anyway emits static functions and tables
        # with no caller, which -Wunused-function and
        # -Wunused-const-variable reject under -Werror.
        if _infer_c_type(node)["kind"] == "array_object":
            items = node.get("items", {})
            if isinstance(items, dict):
                yield from collect_scopes(items, prefix, path, paths)
    # $defs / definitions are intentionally NOT descended into: they are
    # reachable only through $ref, which this generator degrades to a raw JSON
    # fragment, so a def is never referenced by a generated struct.  Emitting a
    # scope for one would produce dead code, and — because the def name was not
    # folded into the scope path — collide with the enclosing scope's C
    # identifier and abort generation.


def _required_set(node: dict) -> set:
    """Return the set of required property names from a JSON Schema object node."""
    return set(node.get("required", []))


def _is_dynamic_object(prop_schema: dict) -> bool:
    """True when the schema node is an object with no fixed ``properties``
    (missing, or an empty ``properties: {}``), meaning it carries no named
    fields and its content is kept as a raw JSON fragment at runtime.

    An empty ``properties: {}`` must be treated as dynamic too: collect_scopes
    only emits a struct scope when a property set is non-empty, so classifying
    an empty-property object as a struct field would reference a ``struct`` type
    that is never defined (and helper functions never generated)."""
    return (
        isinstance(prop_schema, dict)
        and prop_schema.get("type") == "object"
        and not prop_schema.get("properties")
    )


def _infer_c_type(prop_schema: dict) -> dict:
    """Return a descriptor dict for a single JSON Schema property.

    Keys:
        kind        : 'string' | 'int' | 'uint' | 'double' | 'bool' |
                      'object' | 'dynamic' | 'array_string' |
                      'array_object' | 'array_primitive'
        c_type      : C type for the struct field: 'int' or 'intmax_t' (int
                      kind), 'unsigned' or 'uintmax_t' (uint kind)
        c_base      : the C base type string (for primitive arrays)

    A boolean subschema (``true`` admits anything, ``false`` nothing) carries
    no type, and neither does tuple-form ``items`` (a list of subschemas): both
    are stored as a raw JSON fragment, and _dynamic_reason says why.
    """
    if not isinstance(prop_schema, dict):
        return {"kind": "dynamic"}
    t = prop_schema.get("type")
    if t == "string":
        return {"kind": "string"}
    if t == "integer":
        # JSON Schema allows non-integral bounds on integer types; tighten
        # them to the nearest integer in the valid direction.
        minimum = prop_schema.get("minimum")
        maximum = prop_schema.get("maximum")
        if minimum is not None:
            minimum = math.ceil(minimum)
        if maximum is not None:
            maximum = math.floor(maximum)
        # No single 64-bit C integer type spans the range → store as a raw
        # JSON fragment. Besides min < INT64_MIN or max > UINT64_MAX, a
        # negative minimum with a maximum above INT64_MAX fits neither
        # intmax_t (max too large) nor uintmax_t (minimum negative).
        if (minimum is not None and minimum < _INT64_MIN) or \
                (maximum is not None and maximum > _UINT64_MAX) or \
                (minimum is not None and minimum < 0 and
                 maximum is not None and maximum > _INT64_MAX):
            return {"kind": "dynamic"}
        # Both bounds explicit → pick the narrowest 32-bit type if possible.
        if minimum is not None and maximum is not None:
            if minimum >= 0 and maximum <= _UINT32_MAX:
                return {"kind": "uint", "c_type": "unsigned"}
            if minimum >= _INT32_MIN and maximum <= _INT32_MAX:
                return {"kind": "int", "c_type": "int"}
        # One or no bound → widest appropriate type.
        if minimum is not None and minimum >= 0:
            return {"kind": "uint", "c_type": "uintmax_t"}
        return {"kind": "int", "c_type": "intmax_t"}
    if t == "number":
        return {"kind": "double"}
    if t == "boolean":
        return {"kind": "bool"}
    if t == "object":
        if _is_dynamic_object(prop_schema):
            return {"kind": "dynamic"}
        return {"kind": "object"}
    if t == "array":
        items = prop_schema.get("items", {})
        if not isinstance(items, dict):
            return {"kind": "dynamic"}
        item_t = items.get("type")
        if item_t == "string":
            return {"kind": "array_string"}
        if item_t == "object" and items.get("properties"):
            # An empty ``properties: {}`` yields no struct scope; fall through
            # to a raw JSON fragment rather than referencing an undefined type.
            return {"kind": "array_object"}
        if item_t == "integer":
            elem = _infer_c_type(items)
            if elem["kind"] == "dynamic":
                return {"kind": "dynamic"}
            return {"kind": "array_primitive", "c_base": elem.get("c_type", "intmax_t")}
        if item_t == "boolean":
            return {"kind": "array_primitive", "c_base": "bool"}
        if item_t == "number":
            return {"kind": "array_primitive", "c_base": "double"}
        return {"kind": "dynamic"}
    return {"kind": "dynamic"}


# ---------------------------------------------------------------------------
# gperf generation
# ---------------------------------------------------------------------------

_GPERF_MACROS = (
    "TOTAL_KEYWORDS",
    "MIN_WORD_LENGTH",
    "MAX_WORD_LENGTH",
    "MIN_HASH_VALUE",
    "MAX_HASH_VALUE",
)

_LINE_DIRECTIVE = re.compile(r'^#line\b')


def _lookup_root(pfx: str, scope_name: str) -> str:
    """Return the shared prefix for every symbol in a scope's lookup table.

    All gperf-derived and gperf-adjacent symbols (the public ``lookup``
    function, the ``hash`` function, the internal ``kv_lookup_`` helper,
    the ``stringpool`` storage macro, and the ``kv`` struct tag) share
    this prefix so the naming convention ``<pfx>_lookup_<scope>`` is
    visible at a glance -- unless a nested scope's own lookup already takes a
    helper's name, in which case _plan_identifiers moves the helpers to
    ``<pfx>_lookup_<scope>_2`` (see _IdentPlan).

    ``_join_ident`` normalises the join: empty parts are dropped (so the
    default empty prefix yields ``lookup_<scope>``, not a reserved leading
    ``_``), and a part already ending in ``_`` -- a user prefix like ``ex_``
    or a keyword-escaped scope name like ``int_`` -- absorbs the separator
    instead of doubling it into an internal ``__`` (see to_c_ident).
    """
    pfx = pfx.rstrip("_")
    return _join_ident(pfx, "lookup", scope_name)


def _make_gperf_input(lookup_name: str, helper_root: str, keys: list) -> str:
    """Build the complete gperf input for a scope's keys.

    gperf's own symbols (the hash and ``kv_lookup_`` functions, the string
    pool and the ``kv`` struct tag) are named from *helper_root*, which is
    *lookup_name* unless _plan_identifiers had to move them off a name a
    nested scope already takes.

    Every option is embedded as a ``%`` declaration so the input file is the
    single source of truth; gperf is then invoked with no command-line
    options (see _run_gperf).  Each declaration is the documented equivalent
    of a former command-line flag:

        %compare-lengths    (-l)  binary comparison: the generated lookup
                                  compares by length + memcmp instead of
                                  assuming NUL-terminated input, and keys may
                                  contain NUL bytes.  Mandatory here.
        %enum               (-E)  emit constants as a local enum, not #define.
        %pic                (-P)  string-pool layout for shared libraries.
        %null-strings             NULL (not "") for empty table slots.
        %define string-pool-name  (-Q) name the %pic string pool.
        %define initializer-suffix  (-F) zero the idx field of empty slots.

    (%compare-strncmp / -c is intentionally omitted: gperf documents it as
    ignored whenever %compare-lengths is in effect, which it always is here.)

    Keys are emitted as double-quoted C-string literals with backslash
    escapes -- gperf's quoted-keyword syntax -- so nearly any byte is
    representable: delimiters, quotes, '%'/'#', control characters, non-ASCII,
    and (because of %compare-lengths) NUL.  '?' is the exception, because
    gperf owns both ends of that round trip and handles neither: it rejects
    the '\\?' escape _c_string_literal emits ("invalid escape sequence in
    string"), and it re-emits a decoded '?' verbatim into its output, where a
    "??" pair would become a trigraph again.  _gperf_safe_keys screens those
    keys out -- along with the empty keyword gperf also refuses -- before we
    get here.
    """
    header_lines = [
        "%language=ANSI-C",
        "%struct-type",
        "%readonly-tables",
        "%compare-lengths",
        "%enum",
        "%pic",
        "%null-strings",
        f"%define string-pool-name {_join_ident(helper_root, 'stringpool')}",
        "%define initializer-suffix ,0",
        f"%define hash-function-name {_join_ident(helper_root, 'hash')}",
        f"%define lookup-function-name {_join_ident(helper_root, 'kv_lookup_')}",
        "%define slot-name name",
        "%{",
        f"/* {lookup_name}: {len(keys)} keys  (auto-generated -- do not edit) */",
        "%}",
        "struct " + _join_ident(helper_root, "kv") + " { int name; int idx; };",
        "%%",
    ]
    keyword_lines = [
        f'"{_c_string_literal(key)[0]}", {i}' for i, key in enumerate(keys)
    ]
    return "\n".join(header_lines) + "\n" + "\n".join(keyword_lines) + "\n%%\n"


def _gperf_safe_keys(keys: list) -> bool:
    """True when gperf can build a lookup table for these keys.

    Keys are emitted as quoted C-string literals (see _make_gperf_input), so
    nearly every byte is representable -- delimiters, quotes, control
    characters, non-ASCII, and (under %compare-lengths) NUL.  Two cases must
    fall back to the bsearch lookup, which emits its keys through
    _c_string_literal directly and has neither restriction:

    * the empty key, the one keyword gperf refuses outright ("Empty input
      keyword is not allowed");
    * a key containing '?', which gperf can neither read (it rejects the
      '\\?' escape _c_string_literal emits) nor write (it prints a decoded
      '?' unescaped, re-forming any trigraph in its own output).
    """
    return all(len(key) > 0 and "?" not in key for key in keys)


def _run_gperf(lookup_name: str, helper_root: str, keys: list) -> str:
    # All options are embedded as %-declarations in the input (see
    # _make_gperf_input), so gperf is invoked with no argv options and the
    # input is fed on stdin.
    src = _make_gperf_input(lookup_name, helper_root, keys)
    try:
        r = subprocess.run(
            ["gperf"],
            input=src,
            capture_output=True,
            text=True,
            check=True,
        )
        return r.stdout
    except FileNotFoundError:
        sys.exit("error: gperf not found -- install it with: apt install gperf")
    except subprocess.CalledProcessError as e:
        sys.exit("error: gperf failed for scope " +
                 repr(lookup_name) + ":\n" + e.stderr)


def _suppress_unused_hash_params(lines: list, hash_name: str) -> list:
    """Cast-to-void whichever of the gperf hash's ``str``/``len`` parameters its
    generated body does not reference, so the hash never trips
    ``-Wunused-parameter``.

    gperf drops ``len`` from the hash when every key that reaches it has the
    same length (the length term is then constant), and drops ``str`` for a
    pure length hash, so which parameter is unused depends on the key set and
    must be detected rather than assumed.  Casting an *used* parameter to void
    as well would be harmless, but emitting only what is needed keeps the
    generated output minimal.
    """
    sig = hash_name + " (register const char *str, register size_t len)"
    sig_idx = next(
        (i for i, ln in enumerate(lines) if ln.rstrip().endswith(sig)), None)
    if sig_idx is None:
        return lines
    brace_idx = next(
        (i for i in range(sig_idx + 1, len(lines)) if lines[i].strip() == "{"),
        None)
    if brace_idx is None:
        return lines
    # Find the function's closing brace by tracking brace depth from the opener
    # (the asso_values initializer braces balance out along the way).
    depth = 0
    end_idx = len(lines) - 1
    for i in range(brace_idx, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0:
            end_idx = i
            break
    body = "".join(lines[brace_idx + 1:end_idx])
    casts = []
    if not re.search(r"\bstr\b", body):
        casts.append(f"{_INDENT}(void)(str);\n")
    if not re.search(r"\blen\b", body):
        casts.append(f"{_INDENT}(void)(len);\n")
    return lines[:brace_idx + 1] + casts + lines[brace_idx + 1:]


def _postprocess_gperf(
        src: str, lookup_name: str, helper_root: str,
        public_lookup: bool = True) -> str:
    """Post-process gperf output for inclusion in the generated .c file.

    - Strip #line directives (they point to gperf's internal buffers).
    - Strip the ASCII charset ``#if !((' ' == 32) && ...)`` guard block;
      the project targets POSIX (ASCII guaranteed) so the check is
      redundant, and stripping it avoids duplicate blocks when multiple
      scopes are processed.
    - Make the internal kv_lookup_ function static so it does not pollute
      the link-time namespace.
    - Suppress -Wunused-parameter on the hash function's ``str`` argument:
      gperf generates ``hash(register const char *str, ...)`` but the
      trivial length-only hash never dereferences ``str``.
    - Append #undef guards for the gperf-emitted #define macros.
    - Append a thin ``int {lookup_name}(...)`` wrapper.  When
      ``public_lookup`` is True the wrapper has external linkage and is
      declared in the generated header; when False it is ``static``.
    """
    lines = src.splitlines(keepends=True)

    # Strip #line directives.
    result = [ln for ln in lines if not _LINE_DIRECTIVE.match(ln)]

    # Strip the gperf ASCII-charset guard block (redundant on POSIX; stripping
    # also avoids duplicate blocks across scopes).  It runs from '#if !((' to
    # its matching #endif; depth tracking tolerates any future nested #if.
    filtered = []
    depth = 0
    for ln in result:
        if depth == 0:
            if ln.startswith("#if !(("):
                depth = 1  # begin skipping
            else:
                filtered.append(ln)
        else:
            stripped = ln.strip()
            if stripped.startswith("#if"):
                depth += 1
            elif stripped == "#endif":
                depth -= 1
            # consume the line either way (skip it)
    result = filtered

    # Make kv_lookup_ static.
    kv_ret = "const struct " + _join_ident(helper_root, "kv") + " *\n"
    result = ["static " + ln if ln == kv_ret else ln for ln in result]

    # Suppress -Wunused-parameter on whichever of the hash's parameters gperf's
    # generated body does not reference.
    result = _suppress_unused_hash_params(
        result, _join_ident(helper_root, "hash"))

    result.append("\n")
    for macro in _GPERF_MACROS:
        result.append("#ifdef " + macro + "\n")
        result.append("#undef " + macro + "\n")
        result.append("#endif\n")

    # Thin wrapper: returns key index or -1.
    storage = "" if public_lookup else "static "
    result += [
        "\n",
        storage + "int\n",
        lookup_name + "(const char *str, size_t len)\n",
        "{\n",
        _INDENT + "const struct " + _join_ident(helper_root, "kv") + " *kv_ = "
        + _join_ident(helper_root, "kv_lookup_") + "(str, len);\n",
        _INDENT + "return kv_ ? kv_->idx : -1;\n",
        "}\n",
    ]
    return "".join(result)


def _generate_bsearch_lookup_c(
        lookup_name: str, helper_root: str, keys: list,
        public_lookup: bool) -> str:
    """Generate a bsearch(3)-based lookup (--optimize size).

    Keys are sorted by (length, name) so the comparator can prune with a
    cheap integer comparison before calling memcmp.  The table, entry type
    and comparator are named from *helper_root* (see _make_gperf_input).
    Requires <stdlib.h> (bsearch) and <string.h> (memcmp).
    """
    tbl = _join_ident(helper_root, "keys_")
    entry_t = _join_ident(helper_root, "entry_")
    cmp_fn = _join_ident(helper_root, "cmp_")
    n = len(keys)
    storage = "" if public_lookup else "static "
    # Sort entries by (byte length, UTF-8 bytes) for the table; the comparator
    # below uses memcmp, so the table order must match byte order (Python str
    # ordering diverges from byte ordering for non-ASCII keys).  Record the
    # original index so the returned idx still matches the enum values
    # assigned in key order.
    sorted_entries = sorted(enumerate(keys), key=lambda x: (
        len(x[1].encode("utf-8")), x[1].encode("utf-8")))
    result = [
        f"typedef struct {{ const char *name; size_t len; int idx; }} {entry_t};",
        f"static const {entry_t} {tbl}[] = {{",
    ]
    for orig_i, key in sorted_entries:
        c_key_esc, c_key_len = _c_string_literal(key)
        result.append(f'{_INDENT}{{"{c_key_esc}", {c_key_len}, {orig_i}}},')
    result += [
        "};",
        f"static int {cmp_fn}(const void *key_, const void *entry_)",
        "{",
        f"{_INDENT}const {entry_t} *k_ = (const {entry_t} *)key_;",
        f"{_INDENT}const {entry_t} *e_ = (const {entry_t} *)entry_;",
        f"{_INDENT}if (k_->len < e_->len) {{ return -1; }}",
        f"{_INDENT}if (k_->len > e_->len) {{ return  1; }}",
        f"{_INDENT}return memcmp(k_->name, e_->name, k_->len);",
        "}",
        f"{storage}int",
        f"{lookup_name}(const char *str, size_t len)",
        "{",
        f"{_INDENT}const {entry_t} key_ = {{str, len, 0}};",
        f"{_INDENT}const {entry_t} *e_ =",
        f"{_INDENT * 2}bsearch(&key_, {tbl}, {n}, sizeof(*{tbl}), {cmp_fn});",
        f"{_INDENT}return e_ ? e_->idx : -1;",
        "}",
        "",
    ]
    return "\n".join(result)


# Sentinel for "no default present" — distinguishes missing from default=0/false/""
_MISSING = object()


def _c_string_literal(s: str) -> tuple:
    """Return (escaped C string literal content, byte length) for *s*.

    The byte length counts the UTF-8 bytes of *s*, which is what the emitted
    literal holds: every escape produced here stands for exactly one byte, so
    a length constant emitted beside the literal always matches it.
    """
    encoded = s.encode("utf-8")
    parts = []
    for byte in encoded:
        if byte == ord("\\"):
            parts.append("\\\\")
        elif byte == ord('"'):
            parts.append('\\"')
        elif byte == ord("\n"):
            parts.append("\\n")
        elif byte == ord("\r"):
            parts.append("\\r")
        elif byte == ord("\t"):
            parts.append("\\t")
        elif byte == ord("?"):
            # '?' is escaped although it is printable: the project compiles as
            # -std=c11 (CMAKE_C_EXTENSIONS OFF), where "??" followed by one of
            # =/'()!<>- is a trigraph the compiler folds into a single
            # character before the literal is formed.  That shortens the
            # string while the length constant emitted beside it still counts
            # the source bytes -- an out-of-bounds memcmp -- and "??/" folds
            # into a backslash, which escapes whatever follows, up to and
            # including the closing quote.  '\?' is a standard simple escape
            # sequence (C11 6.4.4.4) denoting one '?' byte, so no trigraph can
            # form no matter what the neighbouring bytes are.
            parts.append("\\?")
        elif 0x20 <= byte <= 0x7E:
            parts.append(chr(byte))
        else:
            # Three-digit octal: unlike \xNN, an octal escape consumes at
            # most three digits, so a following literal hex digit cannot be
            # absorbed into the escape sequence.
            parts.append(f"\\{byte:03o}")
    return "".join(parts), len(encoded)


def _json_escape(s: str) -> str:
    """Return s escaped for JSON string content (without surrounding quotes).

    The function backend bakes the result into the output as literal text, so
    it must escape exactly what the generic runtime's json_marshal_string
    escapes at run time -- '"', '\\', the five short escapes, and C0 controls
    as lowercase \\uXXXX -- and nothing else.  ``ensure_ascii`` is therefore
    off: json.dumps would otherwise spell a non-ASCII character as \\uXXXX,
    where json_marshal_string passes its UTF-8 bytes through, and the two
    backends would emit different (both valid) JSON for the same key.
    """
    return json.dumps(s, ensure_ascii=False)[1:-1]


def _default_designated_init(
        fname: str, kind: str, desc: dict, default_val,
        indent: "str | None" = None) -> "str | None":
    """Return a C designated initializer for a field default, or None.

    A ``default`` is screened against the field's JSON type exactly as
    ``const``/``enum`` are (_const_matches_kind): the value initialises an
    instance of the field, so one of another JSON type is no more meaningful
    here than in a ``const``, and coercing it -- Python truthiness turning
    ``"default": "false"`` into ``true``, ``int()`` truncating 1.9 to 1 or
    raising on ``null`` -- is exactly the silent coercion those two keywords
    already refuse.
    Kinds that carry no emitted default (arrays, dynamic fragments) return
    None as before, unscreened: nothing is generated from the value at all.
    """
    if indent is None:
        indent = _INDENT * 2
    if kind in ("bool", "int", "uint", "double", "string"):
        if not _const_matches_kind(default_val, kind):
            sys.exit(
                f"error: field {fname!r}: default value {default_val!r} has "
                f"JSON type {_json_type_name(default_val)} but the field is "
                f"{kind}; no instance of the field can hold it")
    if kind == "bool":
        return f"{indent}.{fname} = {'true' if default_val else 'false'},"
    if kind == "int":
        n = int(default_val)
        c_type = desc.get("c_type", "intmax_t")
        lit = _c_num_literal(n, kind, c_type)
        return f"{indent}.{fname} = {lit},"
    if kind == "uint":
        n = int(default_val)
        c_type = desc.get("c_type", "uintmax_t")
        lit = _c_num_literal(n, kind, c_type)
        return f"{indent}.{fname} = {lit},"
    if kind == "double":
        # route through _c_num_literal so a non-finite default is rejected
        # rather than emitted as the bare token inf/nan
        return f"{indent}.{fname} = {_c_num_literal(default_val, 'double', '')},"
    if kind == "string":
        escaped, byte_len = _c_string_literal(default_val)
        return f"{indent}.{fname} = {{ .str = \"{escaped}\", .len = {byte_len} }},"
    return None


def _collect_object_defaults(
        scope_name: str, schema_pfx: str, scopes_map: dict,
        indent: "str | None" = None) -> list:
    """Recursively collect C designated-initializer lines for all fields with
    defaults in *scope_name*, including defaults inside nested object fields.

    Returns a (possibly empty) list of C source strings.  Each string is
    indented by *indent*.  Nested object fields produce a block of the form::

        .fname = {
            .child_field = default_val,
        },

    Array fields are skipped — C pointer fields cannot be safely
    initialised with a JSON Schema array default.
    """
    if indent is None:
        indent = _INDENT * 2
    scope_data = scopes_map.get(scope_name)
    if scope_data is None:
        return []
    keys, node = scope_data
    fname_map = _make_field_map(keys, node)
    result = []
    for key in keys:
        prop = node["properties"][key]
        desc = _infer_c_type(prop)
        kind = desc["kind"]
        fname = fname_map[key]
        if kind == "object":
            child_scope = _scope_of_child(
                _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
            child_lines = _collect_object_defaults(
                child_scope, schema_pfx, scopes_map, indent + _INDENT)
            if child_lines:
                result.append(f"{indent}.{fname} = {{")
                result += child_lines
                result.append(f"{indent}}},")
        elif isinstance(prop, dict):
            default_val = prop.get("default", _MISSING)
            if default_val is _MISSING:
                continue
            init_str = _default_designated_init(
                fname, kind, desc, default_val, indent)
            if init_str is not None:
                result.append(init_str)
    return result


def _try_single_byte_lookup(
        lookup_name: str, keys: list, public_lookup: bool) -> "str | None":
    """Return C source for a single-byte switch lookup, or None.

    Scans byte positions 0..min_key_len-1 (UTF-8 byte positions, matching
    the memcmp-based confirmation and the runtime key bytes).  The first
    position where every key has a distinct byte becomes the switch
    discriminator, avoiding the need for gperf.  Each case performs a
    full-length memcmp to confirm the match, so the result is correct even
    when two keys share a prefix.
    """
    if not keys:
        return None
    encoded = [k.encode("utf-8") for k in keys]
    min_len = min(len(e) for e in encoded)
    for pos in range(min_len):
        bytes_at = [e[pos] for e in encoded]
        if len(set(bytes_at)) < len(keys):
            continue
        storage = "" if public_lookup else "static "
        lines = [
            f"{storage}int",
            f"{lookup_name}(const char *str, size_t len)",
            "{",
            f"{_INDENT}if (len < {pos + 1}) {{ return -1; }}",
            f"{_INDENT}switch ((unsigned char)str[{pos}]) {{",
        ]
        for i, key in enumerate(keys):
            b = encoded[i][pos]
            if 0x20 <= b <= 0x7E and chr(b) not in ("'", "\\"):
                case_label = f"'{chr(b)}'"
            else:
                case_label = f"0x{b:02x}"
            c_key_esc, c_key_len = _c_string_literal(key)
            lines.append(f"{_INDENT}case {case_label}:")
            lines.append(
                f"{_INDENT * 2}return len == {c_key_len} && "
                f"memcmp(str, \"{c_key_esc}\", {c_key_len}) == 0 ? {i} : -1;")
        lines += [
            f"{_INDENT}default: return -1;",
            f"{_INDENT}}}",
            "}",
            "",
        ]
        return "\n".join(lines)
    return None


# ---------------------------------------------------------------------------
# Codec generation helpers
# ---------------------------------------------------------------------------

def _ext(scope_name: str, pfx: str) -> str:
    """Return the external identifier for a scope by prepending the user prefix.

    Applies to struct tags, enum tags, and the lookup-table struct tag, where
    the identifier carries only a module+scope prefix (no verb).  The prefix
    is joined the way make_fn_name joins it -- with or without its trailing
    underscore (``ex`` or ``ex_``) a single separator results -- so one
    ``--prefix`` spells the tags and the functions alike.
    """
    return _join_ident(pfx.rstrip("_"), scope_name)


def make_fn_name(verb: str, scope_name: str, pfx: str, suffix: str = "") -> str:
    """Build a generated function name with the verb in the middle.

    The naming convention is ``<prefix>_<verb>_<scope>`` (or with a trailing
    ``<suffix>`` segment, e.g. ``<prefix>_unmarshal_<scope>_<field>`` for the
    per-field array helpers).  The scope part is identical to the struct tag
    produced by ``_ext``, so the function name always reveals the encoded
    struct at a glance.

    The user-supplied prefix may be passed with or without a trailing
    underscore (``ex`` or ``ex_``); a single separator is inserted between
    the prefix and the verb so the result is always exactly one underscore
    wide.  ``_join_ident`` likewise absorbs the separator when the scope name
    itself ends in ``_`` (a keyword-escaped stem such as ``int_``), so the
    suffix join never doubles the underscore into an internal ``__``.
    """
    pfx = pfx.rstrip("_")
    parts = [pfx, verb, scope_name]
    if suffix:
        parts.append(suffix)
    return _join_ident(*parts)


def _scope_of_child(parent_path: str, prop_key: str, schema_pfx: str) -> str:
    """Derive the scope name for a nested property (mirrors collect_scopes logic)."""
    child_path = f"{parent_path}.{prop_key}" if parent_path else prop_key
    return _join_ident(schema_pfx, to_c_ident(child_path))


def _path_from_scope(scope_name: str, schema_pfx: str) -> str:
    """Reverse-engineer the JSON path string from a scope name.

    scope_name = schema_pfx                → ""
    scope_name = _join_ident(schema_pfx, path_ident) → path_ident (dots encoded
    as _).  ``_join_ident`` inserts a single '_' between the two, except when
    schema_pfx already ends in '_' (a keyword-escaped stem such as ``int_``),
    where it absorbs the separator -- so strip the schema_pfx and then one
    leading '_' only if the join added one.
    """
    if scope_name == schema_pfx:
        return ""
    assert scope_name.startswith(schema_pfx)
    rest = scope_name[len(schema_pfx):]
    return rest[1:] if rest.startswith("_") else rest


# ---------------------------------------------------------------------------
# File-scope identifier planning
# ---------------------------------------------------------------------------

# The file-scope names codec/json.h declares.  The generated header includes
# it, so a generated tag or ordinary identifier spelled like one of these is a
# redefinition -- reachable whenever the generated names start with "json_",
# i.e. a schema named json_schema.json (or json.json) with no --prefix, or a
# --prefix of json_.  scripts/gen_schema_test.py cross-checks these sets
# against the header, so a name added there without being added here fails
# the test suite.
_JSON_H_TAGS = frozenset({
    "json_constraint", "json_field", "json_schema", "json_string",
    "json_type", "json_type_kind", "json_val",
})
_JSON_H_ORDINARY = frozenset({
    # functions
    "json_arr_next", "json_free", "json_iswhitespace", "json_marshal",
    "json_marshal_string", "json_obj_next", "json_parse", "json_parse_bool",
    "json_parse_double", "json_parse_imax", "json_parse_int",
    "json_parse_string", "json_parse_uint", "json_parse_umax",
    "json_unmarshal",
    # typedefs
    "json_iter",
    # enumerators
    "JSON_ARRAY", "JSON_BOOL", "JSON_C_CONST", "JSON_C_ENUM",
    "JSON_C_EXCL_MAX", "JSON_C_EXCL_MIN", "JSON_C_MAX", "JSON_C_MAX_ITEMS",
    "JSON_C_MAX_LEN", "JSON_C_MIN", "JSON_C_MIN_ITEMS", "JSON_C_MIN_LEN",
    "JSON_C_MULT", "JSON_ERROR", "JSON_K_BOOL", "JSON_K_DOUBLE",
    "JSON_K_DYNAMIC", "JSON_K_IMAX", "JSON_K_INT", "JSON_K_OBJECT",
    "JSON_K_STRING", "JSON_K_UINT", "JSON_K_UMAX", "JSON_NEXT_END",
    "JSON_NEXT_ERROR", "JSON_NEXT_ITEM", "JSON_NULL", "JSON_NUMBER",
    "JSON_OBJECT", "JSON_STRING",
})
_JSON_H_MACROS = frozenset({"CODEC_JSON_H"})

# What a struct or enum tag may not be: a keyword or a macro.  Typedef names
# live in the ordinary namespace, so a tag may reuse one.
_TAG_RESERVED = _C_KEYWORDS - _TYPEDEF_NAMES


def _lookup_kind(keys: list, optimize: str) -> str:
    """Return which key-lookup implementation a scope gets.

    ``switch`` (a single-byte discriminator, no helper symbols), ``bsearch``
    (--optimize size, or a key gperf cannot index) or ``gperf``.  process()
    emits exactly the kind this returns, and _plan_identifiers reserves the
    helper names of exactly that kind.
    """
    if _try_single_byte_lookup("", keys, public_lookup=False) is not None:
        return "switch"
    if optimize == "size" or not _gperf_safe_keys(keys):
        return "bsearch"
    return "gperf"


def _lookup_helper_names(root: str, kind: str) -> dict:
    """Return {namespace: [names]} for the file-scope helpers a lookup of
    *kind* derives from *root*: the ordinary namespace (functions, variables,
    typedefs), the tag namespace, and macros (which reach every namespace)."""
    if kind == "gperf":
        return {
            "ordinary": [_join_ident(root, "hash"),
                         _join_ident(root, "kv_lookup_"),
                         _join_ident(root, "stringpool_contents")],
            "tag": [_join_ident(root, "kv"),
                    _join_ident(root, "stringpool_t")],
            "macro": [_join_ident(root, "stringpool")],
        }
    if kind == "bsearch":
        return {
            "ordinary": [_join_ident(root, "keys_"),
                         _join_ident(root, "entry_"),
                         _join_ident(root, "cmp_")],
            "tag": [],
            "macro": [],
        }
    return {"ordinary": [], "tag": [], "macro": []}


class _IdentPlan:
    """The file-scope identifiers one generated .gen.{h,c} pair defines.

    It covers the file-scope names one scope's naming can collide with across
    scopes: each is either part of the naming convention -- a struct tag, a
    per-scope free/unmarshal/marshal/lookup function, a key enumerator -- or a
    helper derived from a scope's name by a fixed suffix:
    the key enum's tag (``<ename>_key``), the lookup's gperf/bsearch helpers
    (``<lookup>_hash``, ``<lookup>_stringpool``, ``<lookup>_keys_``, ...),
    the fast backend's ``<marshal>_impl``, and the size backend's descriptor
    tables (``<ename>_schema``, ``<ename>_fields``, ``<ename>_defaults`` and
    the per-field ``<ename>_<field>_c`` / ``<ename>_<field>_enum``).  A scope
    name encodes its JSON path with '_', so a nested object property spelled
    like one of those suffixes ("key", "hash", "impl", ...) gives a child
    scope whose own convention-derived name is exactly the parent's helper
    name; and every scope name begins with the stem, so a stem spelled like a
    verb ("lookup", "free", ...) makes a scope's ``<pfx><verb>_<scope>``
    function reach the tables of a scope ``<verb>_...``.  No fixed suffix can
    rule that out -- it only moves which property collides.

    So the convention names are claimed first, and each helper is then
    assigned the plain name it has always had unless that would clash, in
    which case '_2', '_3', ... is appended to its root (the same rule
    _make_array_helper_map applies to the array helpers).  Output for a schema
    without such a clash is unchanged.  A convention name is part of the
    generated API, so a clash between two of them -- or with codec/json.h or
    a macro the generated code has in scope -- is instead an error naming the
    property, like the scope and enum-constant collision guards.  Other
    emitted names stay outside the plan: the per-field array helpers are
    settled by _make_array_helper_map and the struct members by
    _make_field_map, and the fast marshal's static emitters are not planned.
    The descriptor tables are assigned by generate_tables_c as it emits them
    (see table), after every name planned here, so a table only ever yields.
    """

    def __init__(self, scope_paths: dict):
        self._paths = scope_paths
        self.ordinary: dict = {}
        self.tag: dict = {}
        self.macro: dict = {}
        self.members: set = set()
        self.enum_tag: dict = {}
        self.lookup_helper_root: dict = {}
        self.marshal_impl: dict = {}
        self.schema_table: dict = {}

    def where(self, scope_name: str) -> str:
        path = self._paths.get(scope_name, "")
        return f"property {path!r}" if path else "the root object"

    @staticmethod
    def _foreign(ns: str, name: str) -> "str | None":
        """Return what already owns *name* outside the generated code."""
        if name in _JSON_H_MACROS or (
                ns == "tag" and name in _JSON_H_TAGS) or (
                ns != "tag" and name in _JSON_H_ORDINARY):
            return "a name codec/json.h declares"
        if name in (_TAG_RESERVED if ns == "tag" else _C_KEYWORDS):
            return "a C keyword, type name or standard macro"
        return None

    def _free(self, ns: str, name: str) -> bool:
        if self._foreign(ns, name) is not None or name in self.macro:
            return False
        if ns == "macro":
            return name not in self.ordinary and name not in self.tag \
                and name not in self.members
        return name not in getattr(self, ns)

    def claim(self, ns: str, name: str, owner: str) -> None:
        """Claim a naming-convention identifier, or exit naming the clash."""
        foreign = self._foreign(ns, name)
        if foreign is not None:
            hint = "pass a --prefix other than json_ to move the generated " \
                "names out of codec/json.h's json_ namespace" \
                if foreign.startswith("a name codec") \
                else "rename the property or pass --prefix"
            sys.exit(f"error: {owner} would be {name!r}, which is {foreign}; "
                     f"{hint}")
        table = getattr(self, ns)
        other = self.macro.get(name) or table.get(name)
        if other is not None and other != owner:
            sys.exit(f"error: generated identifier collision: {other} and "
                     f"{owner} would both be {name!r}; rename the "
                     "conflicting properties")
        table[name] = owner

    def assign(self, base: str, derive) -> str:
        """Return the first of *base*, *base*_2, ... whose derived helper
        names -- ``derive(root)`` → {namespace: [names]} -- are all free, and
        claim them."""
        root, n = base, 1
        while True:
            names = derive(root)
            if all(self._free(ns, name)
                   for ns, group in names.items() for name in group):
                break
            n += 1
            root = _join_ident(base, str(n))
        for ns, group in names.items():
            for name in group:
                getattr(self, ns)[name] = f"a helper of {root!r}"
        return root

    def table(self, base: str) -> str:
        """Assign a size-backend descriptor table the first free one of
        *base*, *base*_2, ...  Called only for a table that is emitted, so an
        omitted table never moves another off its plain name."""
        return self.assign(base, lambda root: {"ordinary": [root]})


def _plan_identifiers(
        scopes: list, scope_paths: dict, pfx: str, opts,
        guard: str) -> _IdentPlan:
    """Claim every naming-convention identifier the output defines, then
    assign each suffix-derived helper a name that clashes with none of them.
    See _IdentPlan."""
    plan = _IdentPlan(scope_paths)
    use_tables = opts.optimize == "size"
    root_scope = scopes[0][0]
    emit_lookup = opts.do_lookup or opts.do_unmarshal
    emit_enum = opts.do_lookup or (opts.do_unmarshal and not use_tables)
    plan.macro[guard] = "the header guard"

    for scope_name, keys, node in scopes:
        where = plan.where(scope_name)
        is_public = opts.sub_schema or scope_name == root_scope
        ename = _ext(scope_name, pfx)
        if opts.do_structs:
            plan.claim("tag", ename, f"the struct tag of {where}")
            fname_map = _make_field_map(keys, node)
            for key in keys:
                fname = fname_map[key]
                companion = _derived_member(
                    _infer_c_type(node["properties"][key])["kind"], fname)
                for member in (fname, companion):
                    if member is None:
                        continue
                    # Only the header guard is planned yet, and every helper
                    # macro planned later steers clear of the members; a
                    # member the guard's empty definition erased would leave
                    # a struct that no longer parses.
                    if member in plan.macro:
                        sys.exit(f"error: the struct member for key {key!r} "
                                 f"of {where} would be {member!r}, which is "
                                 f"{plan.macro[member]}; rename the property "
                                 "or pass --prefix")
                    plan.members.add(member)
        for verb, on in (
                ("free", opts.do_structs and (is_public or not use_tables)),
                ("unmarshal",
                 opts.do_unmarshal and (is_public or not use_tables)),
                ("marshal", opts.do_marshal and is_public)):
            if on:
                plan.claim("ordinary", make_fn_name(verb, scope_name, pfx),
                           f"the {verb} function of {where}")
        if emit_lookup:
            plan.claim("ordinary", _lookup_root(pfx, scope_name),
                       f"the lookup function of {where}")
        if emit_enum:
            for key, const in _make_enum_const_map(keys, node, ename).items():
                plan.claim("ordinary", const,
                           f"the enumerator for key {key!r} of {where}")

    for scope_name, keys, node in scopes:
        ename = _ext(scope_name, pfx)
        if emit_enum:
            tag = plan.assign(_join_ident(ename, "key"), lambda root: {
                "tag": [root]})
            if opts.do_lookup and tag != _join_ident(ename, "key"):
                print(f"  note: the key enum of {plan.where(scope_name)} is "
                      f"named {tag!r}; the plain name is taken",
                      file=sys.stderr)
            plan.enum_tag[scope_name] = tag
        if emit_lookup:
            kind = _lookup_kind(keys, opts.optimize)
            plan.lookup_helper_root[scope_name] = plan.assign(
                _lookup_root(pfx, scope_name),
                lambda root, kind=kind: _lookup_helper_names(root, kind))
        if opts.do_marshal and not use_tables:
            plan.marshal_impl[scope_name] = plan.assign(
                make_fn_name("marshal", scope_name, pfx, suffix="impl"),
                lambda root: {"ordinary": [root]})
    return plan


# ---------------------------------------------------------------------------
# Struct header generation
# ---------------------------------------------------------------------------

def generate_structs_h(
        scopes: list, pfx: str, schema_pfx: str) -> list:
    """Return header lines for struct definitions.

    Scopes must be in *reverse* order (innermost first) so that nested structs
    are declared before the structs that embed them.

    Layout per struct: fields are grouped by C type (objects, strings,
    arrays, dynamic JSON fragments, unsigned integers, signed integers,
    doubles, booleans), sorted alphabetically within each group, so that
    fields of equal size and alignment stay contiguous.
    """
    lines = []
    # scopes list is (scope_name, keys, node) — emit innermost first
    for scope_name, keys, node in reversed(scopes):
        required = _required_set(node)
        ename = _ext(scope_name, pfx)
        fname_map = _make_field_map(keys, node)

        # Collect per-kind field lists.
        groups = {k: [] for k in (
            "object", "string",
            "array_string", "array_object", "array_primitive",
            "dynamic", "uint", "int", "double", "bool",
        )}
        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            kind = desc["kind"]
            fname = fname_map[key]
            is_req = key in required
            groups[kind].append((fname, key, desc, is_req))

        for kind in groups:
            groups[kind].sort(key=lambda x: x[0])

        lines.append(f"struct {ename} {{")

        # Fields grouped by kind, each group sorted alphabetically.
        # A blank line separates successive non-empty groups.
        group_order = (
            "object", "string",
            "array_string", "array_object", "array_primitive",
            "dynamic", "uint", "int", "double", "bool",
        )
        separator_needed = False
        for gkind in group_order:
            entries = groups[gkind]
            if not entries:
                continue
            if separator_needed:
                lines.append("")
            separator_needed = True
            for fname, key, desc, _ in entries:
                kind = desc["kind"]
                if kind == "string":
                    lines.append(f"{_INDENT}struct json_string {fname};")
                elif kind == "int":
                    c_type = desc.get("c_type", "intmax_t")
                    lines.append(f"{_INDENT}{c_type} {fname};")
                elif kind == "uint":
                    c_type = desc.get("c_type", "uintmax_t")
                    lines.append(f"{_INDENT}{c_type} {fname};")
                elif kind == "double":
                    lines.append(f"{_INDENT}double {fname};")
                elif kind == "bool":
                    lines.append(f"{_INDENT}bool {fname};")
                elif kind == "object":
                    child_scope = _scope_of_child(
                        _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                    lines.append(
                        f"{_INDENT}struct {_ext(child_scope, pfx)} {fname};")
                elif kind == "dynamic":
                    lines.append(f"{_INDENT}struct json_string {_json_member(fname)};")
                elif kind == "array_string":
                    lines.append(f"{_INDENT}struct json_string *{fname};")
                    lines.append(f"{_INDENT}size_t {_count_member(fname)};")
                elif kind == "array_object":
                    child_scope = _scope_of_child(
                        _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                    child_ename = _ext(child_scope, pfx)
                    lines.append(f"{_INDENT}/* {child_ename} array */")
                    lines.append(f"{_INDENT}struct {child_ename} *{fname};")
                    lines.append(f"{_INDENT}size_t {_count_member(fname)};")
                elif kind == "array_primitive":
                    c_base = desc.get("c_base", "int")
                    lines.append(f"{_INDENT}/* {c_base} array */")
                    lines.append(f"{_INDENT}{c_base} *{fname};")
                    lines.append(f"{_INDENT}size_t {_count_member(fname)};")

        lines.append("};")
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Header prototypes (free / unmarshal / marshal) and schema-support warnings
# ---------------------------------------------------------------------------

def generate_free_h(scopes: list, pfx: str, sub_schema: bool = False) -> list:
    """Return header lines declaring the ``free`` functions."""
    lines = []
    root_scope = scopes[0][0]
    for scope_name, _, _ in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        lines += [
            "/** @brief Free heap-allocated fields inside *obj (arrays). */",
            f"void {make_fn_name('free', scope_name, pfx)}(struct {ename} *obj);",
            "",
        ]
    return lines


# JSON Schema keywords the generator consumes structurally or treats as pure
# annotations; their presence on a node never means a dropped constraint.
# ``enum``/``const`` are constraints, not structure: only the scalar kinds emit
# a check for them, so they are listed per kind in _ENFORCED_KEYWORDS below.
_RECOGNIZED_KEYWORDS = frozenset({
    # structure the generator acts on
    "type", "properties", "items", "required", "additionalProperties",
    "default",
    # core / annotation keywords with no code-generation effect by design
    "title", "description", "$comment", "examples", "deprecated",
    "readOnly", "writeOnly", "$schema", "$id", "$ref", "$anchor",
    "$defs", "definitions",
})

# Constraint keywords the generator actually enforces, keyed by inferred kind.
# Both backends stay in lockstep here: _scalar_constraint_checks (fast) and
# _build_constraint_c (size) emit checks for exactly these.
_ENFORCED_KEYWORDS = {
    "string": frozenset({"minLength", "maxLength", "enum", "const"}),
    "int": frozenset(
        {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
         "multipleOf", "enum", "const"}),
    "uint": frozenset(
        {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
         "multipleOf", "enum", "const"}),
    "double": frozenset(
        {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
         "multipleOf", "enum", "const"}),
    "bool": frozenset({"enum", "const"}),
    "array_string": frozenset({"minItems", "maxItems"}),
    "array_primitive": frozenset({"minItems", "maxItems"}),
    "array_object": frozenset({"minItems", "maxItems"}),
}


def _dynamic_reason(prop) -> str:
    """Explain why *prop* degrades to a raw JSON fragment (a ``dynamic`` kind
    that is not a deliberate dynamic object)."""
    if prop is False:
        return ("boolean subschema false (no value is allowed) is not "
                "enforced")
    if not isinstance(prop, dict):
        return "boolean subschema"
    if "$ref" in prop:
        return "$ref is not resolved"
    if isinstance(prop.get("type"), list):
        return "union types are not supported"
    if "type" not in prop:
        return "no 'type' keyword"
    if prop.get("type") == "array":
        items = prop.get("items")
        if isinstance(items, list):
            return "tuple-form items are not supported"
        if items is False:
            return ("items: false (only an empty array is allowed) is not "
                    "enforced")
        return "unsupported array item type"
    if prop.get("type") == "integer":
        return "integer bounds exceed the 64-bit range"
    return "unsupported construct"


def _warn_dropped_keywords(prop: dict, kind: str, path: str) -> None:
    """Warn for each keyword on *prop* that the generator emits no check for,
    so a constraint the author wrote -- e.g. a string ``pattern`` or ``format``
    -- is not dropped without a diagnostic."""
    recognized = _RECOGNIZED_KEYWORDS | _ENFORCED_KEYWORDS.get(
        kind, frozenset())
    for key in sorted(prop):
        if key not in recognized:
            print(
                f"  warning: property {path!r}: keyword {key!r} is not "
                "enforced by the generator; the constraint is ignored",
                file=sys.stderr)


def _warn_unsupported_props(
        node, path: str = "", strict: bool = False,
        check_own: bool = False) -> None:
    """Print a warning for schema constructs the generator does not honor:
    a property that degrades to a raw JSON fragment for a reason the author may
    not expect ($ref, union types, missing type, a boolean subschema,
    unsupported or tuple-form array items, out-of-range integer bounds); a
    constraint keyword the generator emits no check for; a ``required`` name
    with no ``properties`` entry, which no generated field tracks; and an
    ``additionalProperties: false`` node that is inert without ``--strict``.
    Deliberately dynamic objects (additionalProperties without fixed
    properties) are not warned about."""
    if not isinstance(node, dict):
        return
    # 'additionalProperties: false' is honored only by the per-object key switch
    # that --strict tightens, and only a property-bearing object gets that
    # switch.  Warn when the constraint is therefore inert -- but the remedy
    # differs: a property-bearing object needs --strict (so warn only when it is
    # off), while a property-less object is stored as a raw JSON fragment and can
    # never reject keys, so --strict is not the fix -- warn regardless and say so.
    if node.get("type") == "object" \
            and node.get("additionalProperties") is False:
        if "properties" not in node:
            print(
                f"  warning: {path or '<root>'}: 'additionalProperties: false' "
                "has no effect on an object with no fixed properties; it is "
                "stored as a raw JSON fragment and unknown keys are accepted",
                file=sys.stderr)
        elif not strict:
            print(
                f"  warning: {path or '<root>'}: 'additionalProperties: false' "
                "has no effect without --strict; unknown keys are accepted",
                file=sys.stderr)
    # Only a key with a 'properties' entry becomes a field, and only a field is
    # tracked as required, so a 'required' name without one is never checked:
    # an instance lacking it is accepted.  On a property-bearing object --strict
    # also rejects that key as unknown, leaving the schema unsatisfiable.
    if node.get("type") == "object" and isinstance(node.get("required"), list):
        props = node.get("properties")
        props = props if isinstance(props, dict) else {}
        for name in sorted(set(node["required"]) - set(props)):
            note = ("; --strict also rejects the key, so no instance can "
                    "satisfy the schema") if strict and props else ""
            print(
                f"  warning: {path or '<root>'}: required property {name!r} "
                "has no 'properties' entry; the requirement is not "
                f"enforced{note}", file=sys.stderr)
    # Check this node's OWN dropped-constraint keywords when it is reached as a
    # subtree root -- the top-level schema, or a $defs/definitions entry -- since
    # no parent properties-loop or array-items visit covers it.  Nested
    # properties and array items are checked by their parent below and pass
    # check_own=False to avoid a double warning.  A dynamic node carries no
    # enforceable constraint, so skip it.
    if check_own:
        own_kind = _infer_c_type(node)["kind"]
        if own_kind != "dynamic":
            _warn_dropped_keywords(node, own_kind, path or "<root>")
    if node.get("type") == "object" and "properties" in node:
        for key, prop in sorted(node["properties"].items()):
            ppath = f"{path}.{key}" if path else key
            if not isinstance(prop, dict):
                print(
                    f"  warning: property {ppath!r}: {_dynamic_reason(prop)}; "
                    "the value is stored as a raw JSON fragment",
                    file=sys.stderr)
                continue
            desc = _infer_c_type(prop)
            if desc["kind"] == "dynamic" and not _is_dynamic_object(prop):
                print(
                    f"  warning: property {ppath!r}: {_dynamic_reason(prop)}; "
                    "the value is stored as a raw JSON fragment",
                    file=sys.stderr)
            else:
                _warn_dropped_keywords(prop, desc["kind"], ppath)
            _warn_unsupported_props(prop, ppath, strict)
    elif node.get("type") == "array" and isinstance(node.get("items"), dict):
        item = node["items"]
        idesc = _infer_c_type(item)
        if idesc["kind"] != "dynamic":
            _warn_dropped_keywords(item, idesc["kind"], path + "[]")
        _warn_unsupported_props(item, path + "[]", strict)
    for defs_key in ("$defs", "definitions"):
        for dname, dnode in sorted(node.get(defs_key, {}).items()):
            _warn_unsupported_props(
                dnode, f"{path}#{dname}" if path else f"#{dname}", strict,
                check_own=True)


def generate_unmarshal_h(scopes: list, pfx: str, sub_schema: bool = False) -> list:
    """Return header lines declaring the ``unmarshal`` functions."""
    lines = []
    root_scope = scopes[0][0]
    for scope_name, _keys, _node in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        lines += [
            "/**",
            " * @brief Unmarshal JSON into *obj; modifies @p json in place.",
            " * @param obj Output; zeroed and given schema defaults before parsing.",
            " * @param json Mutable JSON; @p obj aliases it, so keep it valid in use.",
            " * @param length Length of @p json in bytes.",
            " * @return true on success; on failure, false and *obj reset to all-zero.",
            " */",
            f"bool {make_fn_name('unmarshal', scope_name, pfx)}(",
            f"{_INDENT}struct {ename} *obj, char *json, size_t length);",
            "",
        ]
    return lines


def generate_marshal_h(scopes: list, pfx: str, sub_schema: bool = False) -> list:
    """Return header lines declaring the ``marshal`` functions."""
    lines = []
    root_scope = scopes[0][0]
    for scope_name, _, _ in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        lines += [
            "/**",
            " * @brief Marshal *obj into @p buf as JSON (snprintf semantics).",
            " * @param buf Output buffer, or NULL to only compute the size.",
            " * @param bufsz Size of @p buf in bytes.",
            " * @param obj Object to encode.",
            " * @param indent Per-level indent for pretty output, or NULL for compact.",
            " * @return Byte length excluding NUL (truncates if >= @p bufsz), or -1 on",
            " * error -- including a length this int return cannot represent.",
            " */",
            f"int {make_fn_name('marshal', scope_name, pfx)}(",
            f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj, const char *indent);",
            "",
        ]
    return lines


# ---------------------------------------------------------------------------
# const / enum value typing (shared by both backends)
# ---------------------------------------------------------------------------

def _json_type_name(v) -> str:
    """Name the JSON Schema primitive type of a value decoded from the schema."""
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def _const_matches_kind(v, kind: str) -> bool:
    """True when a const/enum value *v* can equal an instance of a field of the
    scalar *kind* under JSON Schema typed equality.

    JSON booleans, numbers, and strings are distinct types: a boolean never
    equals a number or a string.  Integer and number values compare by numeric
    value, so an integer field also accepts an integer-valued number (2.0 == 2)
    and a number field accepts any number, but a non-integral number can never
    equal an integer instance.  (bool is a Python subclass of int yet a distinct
    JSON type, so it is screened out before the numeric kinds.)
    """
    if kind == "bool":
        return isinstance(v, bool)
    if isinstance(v, bool):
        return False
    if kind == "string":
        return isinstance(v, str)
    if kind in ("int", "uint"):
        if isinstance(v, int):
            return True
        return isinstance(v, float) and v.is_integer()
    if kind == "double":
        return isinstance(v, (int, float))
    return False


def _json_spelling(v) -> str:
    """Spell a schema value *v* as the JSON the author wrote (null, true,
    "yes"), not as the Python object json.load made of it (None, True,
    'yes'), for a diagnostic that quotes it."""
    return json.dumps(v, ensure_ascii=False)


def _unmatchable_reason(v, kind: str, c_type: str) -> "str | None":
    """Explain why a const/enum value *v* can never equal an instance of a
    field of the scalar *kind* stored as C type *c_type*, or None when it can.

    A value is unmatchable two ways, and both mean the same thing -- no
    instance of the field can ever equal it: it is of another JSON type
    (_const_matches_kind), or it is numerically outside the range of the C type
    the field is stored as.  The second is no weaker a verdict than the first:
    a narrow field type is only inferred from an explicit minimum/maximum pair
    that fits it (_infer_c_type), so a value outside that range is outside the
    schema's own declared bounds too, which makes it a property of the schema
    rather than an artefact of the type choice.  Kinds with no integer range
    (string, double, bool) are judged by JSON type alone.
    """
    if not _const_matches_kind(v, kind):
        return (f"has JSON type {_json_type_name(v)}, incompatible with the "
                f"{kind} field")
    if kind in ("int", "uint"):
        type_min, type_max = _C_TYPE_RANGE.get(c_type, (None, None))
        if type_min is not None and not type_min <= int(v) <= type_max:
            return (f"lies outside the range of the {c_type} field "
                    f"([{type_min}, {type_max}])")
    return None


def _filter_const_values(
        values: list, kind: str, field: str, keyword: str,
        c_type: str = "") -> list:
    """Screen a const/enum value list for a field of the scalar *kind* stored
    as C type *c_type*, returning the subset an instance can equal.

    A ``const`` no instance can equal, or an ``enum`` left with no such member,
    is unsatisfiable as written and aborts generation with an error naming the
    field -- coercing it (the former bug) silently turned an impossible schema
    into a validator that accepts data.  A mixed ``enum`` is legal: an
    unmatchable member can never match, so it is dropped with a warning and the
    matchable members are kept.  Dropping is right here and wrong for a bound
    (_check_literal_range): removing a member the field cannot hold leaves the
    validator accepting exactly the same instances, while removing a bound
    would widen what it accepts.

    Both backends screen through this function with the field's own C type, so
    they agree on which schemas are generatable and emit the same member set --
    the size backend then spells the kept values in the wider type its
    descriptor tables store them in.
    """
    if keyword == "enum" and not values:
        sys.exit(
            f"error: field {field!r}: enum must contain at least one item "
            "(an empty enum is unsatisfiable)")
    reasons = [_unmatchable_reason(v, kind, c_type) for v in values]
    kept = [v for v, why in zip(values, reasons) if why is None]
    if keyword == "const":
        if not kept:
            sys.exit(
                f"error: field {field!r}: const value "
                f"{_json_spelling(values[0])} {reasons[0]}; no value can equal "
                "it (unsatisfiable schema)")
        return kept
    for v, why in zip(values, reasons):
        if why is not None:
            print(
                f"  warning: field {field!r}: enum value {_json_spelling(v)} "
                f"{why}; it can never match and is dropped", file=sys.stderr)
    if not kept:
        sys.exit(
            f"error: field {field!r}: enum has no member the {kind} field can "
            "hold; no value can satisfy it (unsatisfiable schema)")
    return kept


# The numeric keywords that bound a field from below; the remaining two bound
# it from above.  Which end a bound applies to decides which side of the
# field's C type range leaves the schema unsatisfiable rather than merely
# constraining nothing.
_LOWER_BOUND_KEYWORDS = frozenset({"minimum", "exclusiveMinimum"})


def _check_bound_satisfiable(
        v: "int | float", keyword: str, field: str, c_type: str) -> None:
    """Abort generation when a numeric bound excludes every value the field
    can hold.

    A narrow field type is inferred only from a ``minimum``/``maximum`` pair
    that fits it (_infer_c_type), so the declared bounds are a subset of the C
    type's range.  A lower bound above that type's maximum -- or an upper bound
    below its minimum -- therefore admits nothing the schema itself allows: the
    schema is unsatisfiable as written, the same verdict an unmatchable
    ``const`` gets (_filter_const_values), and both backends refuse it rather
    than one refusing while the other emits a validator that silently rejects
    every instance.  An exclusive bound admits nothing one step sooner: an
    ``exclusiveMinimum`` equal to the type's maximum, or an
    ``exclusiveMaximum`` equal to its minimum, already leaves no value on the
    admitted side.  Only the far end is an error; a bound past the near end
    merely constrains nothing, and the callers drop it before reaching here.

    ``multipleOf`` is deliberately not screened this way.  It is a divisor, not
    a bound: one the C type cannot hold still leaves 0, which is a multiple of
    every positive divisor, so the schema stays satisfiable and the check is
    widened (_scalar_constraint_checks) instead of refused.
    """
    type_min, type_max = _C_TYPE_RANGE.get(c_type, (None, None))
    if type_min is None:
        return
    n = int(v)
    exclusive = keyword.startswith("exclusive")
    if keyword in _LOWER_BOUND_KEYWORDS:
        satisfiable = n < type_max if exclusive else n <= type_max
    else:
        satisfiable = n > type_min if exclusive else n >= type_min
    if satisfiable:
        return
    sys.exit(
        f"error: field {field!r}: {keyword} {n} excludes every value of the "
        f"{c_type} field ([{type_min}, {type_max}]); no value can satisfy it "
        "(unsatisfiable schema)")


# ---------------------------------------------------------------------------
# Function-backend generation (--optimize fast): bespoke per-scope
# free / unmarshal / marshal functions (faster, larger object code).
# ---------------------------------------------------------------------------

def _scalar_constraint_checks(
        prop_schema: dict,
        kind: str,
        desc: dict,
        val_expr: str,
        indent: str,
        fail_stmt: str = "return false;",
        field: str = "",
) -> list:
    """Return C lines that validate schema constraints on a successfully-parsed field.

    *val_expr* is the C expression for the parsed value:
    - ``string`` kind: a ``json_string`` / ``json_val`` struct; appends ``.str`` / ``.len``.
    - ``int`` / ``uint`` / ``double`` / ``bool`` kind: numeric / boolean expression.

    *fail_stmt* is executed on constraint violation (default ``return false;``;
    array helpers pass ``free(items_); return false;``).

    Supported keywords
    ------------------
    string  : ``minLength``, ``maxLength``, ``const``, ``enum``
    int/uint: ``minimum``, ``maximum``, ``exclusiveMinimum``, ``exclusiveMaximum``,
              ``multipleOf``, ``enum``, ``const``
    double  : same as int/uint (uses floating-point comparisons; ``multipleOf``
              via json_is_multiple_, see _gen_is_multiple_helper)
    bool    : ``enum``, ``const``

    Divergence from JSON Schema: ``minLength``/``maxLength`` compare UTF-8
    *byte* lengths, not Unicode code-point counts.  Non-integral numeric
    bounds on integer fields are tightened to the nearest valid integer.
    """
    lines = []
    c_type = desc.get("c_type", "")

    if kind == "string":
        str_expr = f"{val_expr}.str"
        len_expr = f"{val_expr}.len"
        min_len = prop_schema.get("minLength")
        max_len = prop_schema.get("maxLength")
        const_v = prop_schema.get("const", _MISSING)
        enum_vs = prop_schema.get("enum")

        # The lengths compare against a size_t, so they are coerced to int
        # (a JSON Schema integer may legally arrive as 2.0, whose repr would
        # emit the invalid literal "2.0u") and screened the same way numeric
        # bounds are: `len < 0u` is always false and `len > <above UINT64_MAX>`
        # is unspellable, and either would fail the build under -Werror.
        if min_len is not None:
            min_len = int(min_len)
            if min_len > _UINT64_MAX:
                lines.append(
                    f"{indent}{fail_stmt} /* minLength exceeds any length */")
            elif min_len > 0:
                min_lit = _c_u64_literal(min_len)
                lines.append(
                    f"{indent}if ({len_expr} < {min_lit}) {{ {fail_stmt} }}")
        if max_len is not None:
            max_len = int(max_len)
            if max_len <= _UINT64_MAX:
                max_lit = _c_u64_literal(max_len)
                lines.append(
                    f"{indent}if ({len_expr} > {max_lit}) {{ {fail_stmt} }}")

        def _str_eq(v: str) -> str:
            esc, blen = _c_string_literal(str(v))
            return (f"({len_expr} == {blen}u && "
                    f"memcmp({str_expr}, \"{esc}\", {blen}) == 0)")

        if const_v is not _MISSING:
            _filter_const_values([const_v], "string", field, "const")
            lines.append(f"{indent}if (!{_str_eq(const_v)}) {{ {fail_stmt} }}")
        if enum_vs is not None:
            kept = _filter_const_values(enum_vs, "string", field, "enum")
            conds = " || ".join(_str_eq(v) for v in kept)
            lines.append(f"{indent}if (!({conds})) {{ {fail_stmt} }}")

    elif kind in ("int", "uint"):
        minimum = prop_schema.get("minimum")
        maximum = prop_schema.get("maximum")
        excl_min = prop_schema.get("exclusiveMinimum")
        excl_max = prop_schema.get("exclusiveMaximum")
        mult_of = prop_schema.get("multipleOf")
        const_v = prop_schema.get("const", _MISSING)
        enum_vs = prop_schema.get("enum")

        # JSON Schema allows non-integral bounds on integer types; tighten
        # them to the nearest integer in the valid direction.  Non-integral
        # exclusive bounds become inclusive after rounding (e.g.
        # exclusiveMaximum 2.5 over the integers is exactly maximum 2).
        if minimum is not None:
            minimum = math.ceil(minimum)
        if maximum is not None:
            maximum = math.floor(maximum)
        if excl_min is not None and excl_min != math.floor(excl_min):
            new_min = math.ceil(excl_min)
            minimum = new_min if minimum is None else max(minimum, new_min)
            excl_min = None
        if excl_max is not None and excl_max != math.floor(excl_max):
            new_max = math.floor(excl_max)
            maximum = new_max if maximum is None else min(maximum, new_max)
            excl_max = None

        # Drop a bound whose comparison is always true/false for the C type
        # (an int can never be below INT_MIN, an unsigned never < 0) — emitting
        # it would trip -Wtype-limits under -Werror.
        type_min, type_max = _C_TYPE_RANGE.get(
            c_type, (float("-inf"), float("inf")))
        # What survives that drop is a bound the schema states as significant,
        # so one still outside the C type puts every value the field can hold
        # on the wrong side of it -- an unsatisfiable schema, refused here so
        # both backends refuse it alike.
        if minimum is not None and minimum > type_min:
            _check_bound_satisfiable(minimum, "minimum", field, c_type)
            lines.append(
                f"{indent}if ({val_expr} < {_c_num_literal(minimum, kind, c_type)})"
                f" {{ {fail_stmt} }}")
        if maximum is not None and maximum < type_max:
            _check_bound_satisfiable(maximum, "maximum", field, c_type)
            lines.append(
                f"{indent}if ({val_expr} > {_c_num_literal(maximum, kind, c_type)})"
                f" {{ {fail_stmt} }}")
        if excl_min is not None and excl_min >= type_min:
            _check_bound_satisfiable(
                excl_min, "exclusiveMinimum", field, c_type)
            lines.append(
                f"{indent}if ({val_expr} <= {_c_num_literal(excl_min, kind, c_type)})"
                f" {{ {fail_stmt} }}")
        if excl_max is not None and excl_max <= type_max:
            _check_bound_satisfiable(
                excl_max, "exclusiveMaximum", field, c_type)
            lines.append(
                f"{indent}if ({val_expr} >= {_c_num_literal(excl_max, kind, c_type)})"
                f" {{ {fail_stmt} }}")
        if mult_of is not None:
            if mult_of <= 0 or mult_of != math.floor(mult_of):
                print(
                    f"  warning: non-integral or non-positive multipleOf "
                    f"{mult_of!r} on an integer field is not supported; "
                    f"the check is omitted", file=sys.stderr)
            elif type_min <= mult_of <= type_max:
                lines.append(
                    f"{indent}if ({val_expr} % {_c_num_literal(mult_of, kind, c_type)} != 0)"
                    f" {{ {fail_stmt} }}")
            else:
                # Unlike a bound, a divisor the field's C type cannot hold
                # leaves the schema satisfiable: 0 is a multiple of every
                # positive divisor and lies inside the bounds the narrow type
                # was inferred from.  Take the remainder in the width the
                # divisor does fit -- the same width the descriptor tables
                # store it in, so both backends validate identically -- rather
                # than refuse a schema the size backend generates.
                wide = "uintmax_t" if kind == "uint" else "intmax_t"
                lines.append(
                    f"{indent}if (({wide}){val_expr} %"
                    f" {_c_num_literal(mult_of, kind, wide)} != 0)"
                    f" {{ {fail_stmt} }}")
        # A const/enum value the field cannot hold is screened out here, so
        # every value reaching _c_num_literal below is in range for c_type: an
        # unmatchable const aborts and an unmatchable enum member is dropped,
        # rather than the literal check aborting on a mixed enum that its
        # remaining members still make satisfiable.
        if const_v is not _MISSING:
            _filter_const_values([const_v], kind, field, "const", c_type)
            lines.append(
                f"{indent}if ({val_expr} != {_c_num_literal(const_v, kind, c_type)})"
                f" {{ {fail_stmt} }}")
        if enum_vs is not None:
            kept = _filter_const_values(enum_vs, kind, field, "enum", c_type)
            conds = " && ".join(
                f"{val_expr} != {_c_num_literal(v, kind, c_type)}" for v in kept)
            lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    elif kind == "double":
        minimum = prop_schema.get("minimum")
        maximum = prop_schema.get("maximum")
        excl_min = prop_schema.get("exclusiveMinimum")
        excl_max = prop_schema.get("exclusiveMaximum")
        mult_of = prop_schema.get("multipleOf")
        const_v = prop_schema.get("const", _MISSING)
        enum_vs = prop_schema.get("enum")

        if minimum is not None:
            lines.append(
                f"{indent}if ({val_expr} < {_c_num_literal(minimum, 'double', '')})"
                f" {{ {fail_stmt} }}")
        if maximum is not None:
            lines.append(
                f"{indent}if ({val_expr} > {_c_num_literal(maximum, 'double', '')})"
                f" {{ {fail_stmt} }}")
        if excl_min is not None:
            lines.append(
                f"{indent}if ({val_expr} <= {_c_num_literal(excl_min, 'double', '')})"
                f" {{ {fail_stmt} }}")
        if excl_max is not None:
            lines.append(
                f"{indent}if ({val_expr} >= {_c_num_literal(excl_max, 'double', '')})"
                f" {{ {fail_stmt} }}")
        if mult_of is not None:
            if mult_of <= 0:
                print(
                    f"  warning: non-positive multipleOf {mult_of!r} on a "
                    f"number field is not supported; the check is omitted",
                    file=sys.stderr)
            else:
                lines.append(
                    f"{indent}if (!json_is_multiple_({val_expr}, {_c_num_literal(mult_of, 'double', '')}))"
                    f" {{ {fail_stmt} }}")
        if const_v is not _MISSING:
            _filter_const_values([const_v], "double", field, "const")
            lines.append(
                f"{indent}if ({val_expr} != {_c_num_literal(const_v, 'double', '')})"
                f" {{ {fail_stmt} }}")
        if enum_vs is not None:
            kept = _filter_const_values(enum_vs, "double", field, "enum")
            conds = " && ".join(
                f"{val_expr} != {_c_num_literal(v, 'double', '')}" for v in kept)
            lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    elif kind == "bool":
        const_v = prop_schema.get("const", _MISSING)
        enum_vs = prop_schema.get("enum")

        if const_v is not _MISSING:
            _filter_const_values([const_v], "bool", field, "const")
            lines.append(
                f"{indent}if ({val_expr} != {'true' if const_v else 'false'}) {{ {fail_stmt} }}")
        if enum_vs is not None:
            kept = _filter_const_values(enum_vs, "bool", field, "enum")
            valid = ["true" if v else "false" for v in kept]
            conds = " && ".join(f"{val_expr} != {v}" for v in valid)
            lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    return lines


def _needs_is_multiple(scopes: list) -> bool:
    """True when a validating unmarshal emits a ``number`` multipleOf check.

    That is exactly when _scalar_constraint_checks calls json_is_multiple_:
    a positive ``multipleOf`` on a ``number`` field or on the items of a
    ``number`` array -- one _infer_c_type types as ``array_primitive``, since
    items of any other property (a union type, no type) are never checked.
    The helper is emitted on this same test, so it is never left unused
    (-Werror=unused-function) nor called undeclared."""
    def _checks(schema) -> bool:
        mult = schema.get("multipleOf")
        return (schema.get("type") == "number"
                and isinstance(mult, (int, float))
                and not isinstance(mult, bool) and mult > 0)
    for _, keys, node in scopes:
        for key in keys:
            prop = node["properties"][key]
            if not isinstance(prop, dict):
                continue
            if _checks(prop):
                return True
            if (_infer_c_type(prop)["kind"] == "array_primitive"
                    and _checks(prop["items"])):
                return True
    return False


def _gen_is_multiple_helper() -> list:
    """Return the fast backend's static multipleOf test for doubles.

    A copy of json_fmod, json_exact_below and json_is_multiple in
    codec/json.c, which the size backend's runtime applies: both backends must
    accept the same instances, and none of the helpers is part of the public
    json.h API.  Where the divisor is exactly the decimal the schema wrote (an
    integer, or a fractional dyadic whose exact value has at most DBL_DIG
    significant digits, such as 0.5 or 0.25) and every multiple at the
    instance's magnitude is a double, it must divide the instance exactly;
    otherwise the nearer binary multiple may lie within the operands' decimal
    rounding error (0.3 is not a binary multiple of 0.1, and
    9007199254740993, a multiple of 3, parses to 2^53).  It needs no libm."""
    i1, i2 = _INDENT, _INDENT * 2
    return [
        "static double json_fmod_(double x, double y)",
        "{",
        f"{i1}bool neg = false;",
        f"{i1}if (x < 0) {{",
        f"{i2}x = -x;",
        f"{i2}neg = true;",
        f"{i1}}}",
        f"{i1}if (x < y) {{ return neg ? -x : x; }}",
        f"{i1}double yy = y;",
        f"{i1}while (yy <= x / 2.0) {{ yy *= 2.0; }}",
        f"{i1}while (yy >= y) {{",
        f"{i2}if (x >= yy) {{ x -= yy; }}",
        f"{i2}yy /= 2.0;",
        f"{i1}}}",
        f"{i1}return neg ? -x : x;",
        "}",
        "static double json_exact_below_(const double mult)",
        "{",
        f"{i1}if (json_fmod_(mult, 1.0) == 0.0) {{ return 0x1p53; }}",
        f"{i1}const double digits_max = 1e15;",
        f"{i1}double a = mult;",
        f"{i1}double pow5 = 1.0;",
        f"{i1}double limit = 0x1p53;",
        f"{i1}while (json_fmod_(a, 1.0) != 0.0) {{",
        f"{i2}pow5 *= 5.0;",
        f"{i2}if (pow5 >= digits_max) {{ return 0.0; }}",
        f"{i2}a *= 2.0;",
        f"{i2}limit /= 2.0;",
        f"{i1}}}",
        f"{i1}return a * pow5 < digits_max ? limit : 0.0;",
        "}",
        "static bool json_is_multiple_(const double v, const double mult)",
        "{",
        f"{i1}double r = json_fmod_(v, mult);",
        f"{i1}if (r == 0.0) {{ return true; }}",
        f"{i1}if (r < 0.0) {{ r = -r; }}",
        f"{i1}const double mag = v < 0.0 ? -v : v;",
        f"{i1}if (mag < json_exact_below_(mult)) {{ return false; }}",
        f"{i1}const double dist = r < mult - r ? r : mult - r;",
        f"{i1}return dist <= mag * DBL_EPSILON * (1.0 + DBL_EPSILON);",
        "}",
        "",
    ]


def _has_double_fields(scopes: list) -> bool:
    """True when any scope has a double field or a double array field
    (the marshal functions then need <math.h> for isfinite)."""
    for _, keys, node in scopes:
        for key in keys:
            desc = _infer_c_type(node["properties"][key])
            if desc["kind"] == "double":
                return True
            if (desc["kind"] == "array_primitive"
                    and desc.get("c_base") == "double"):
                return True
    return False


def _has_string_fields(scopes: list) -> bool:
    """True when any scope has a string field or an array-of-string field
    (the marshal functions then emit the json_emit_str_ helper via EMIT_STR)."""
    for _, keys, node in scopes:
        for key in keys:
            if _infer_c_type(node["properties"][key])["kind"] in (
                    "string", "array_string"):
                return True
    return False


def _make_array_helper_map(
        scope_name: str, keys: list, node: dict, pfx: str, fname_map: dict,
        reserved: set) -> dict:
    """Return a mapping JSON property name → array-helper function name.

    Every array field gets one file-local unmarshal helper.  ``arr_`` in the
    suffix keeps the usual name readable but does not by itself make it
    unique: a scope name encodes the JSON path with '_', so the helper for an
    array field ``a`` and the nested-object unmarshal function of a sibling
    property ``arr_a`` both spell ``<pfx>_unmarshal_<scope>_arr_a``, and no
    fixed infix can rule that out -- it only moves which pair of names
    collides.  These helpers are file-local and never named by a caller of the
    generated code, so unlike a scope name or an enum constant (part of the
    generated API, where a clash is an error the schema author must resolve) a
    clash is settled here the way _make_field_map settles a duplicate field
    name: append '_2', '_3', ... in the scope's key order, which is sorted, so
    the choice is deterministic.

    *reserved* holds every name already spoken for -- the unmarshal function
    of every scope in the schema, plus the helpers assigned so far -- and is
    updated in place as names are handed out.
    """
    result = {}
    for key in keys:
        prop = node["properties"][key]
        if not _is_array_kind(_infer_c_type(prop)["kind"]):
            continue
        base = make_fn_name(
            "unmarshal", scope_name, pfx, suffix=f"arr_{fname_map[key]}")
        cand, n = base, 1
        while cand in reserved:
            n += 1
            cand = _join_ident(base, str(n))
        reserved.add(cand)
        result[key] = cand
    return result


def _gen_unmarshal_array_string_helper(
        scope_name: str, pfx: str, fname: str, fn_name: str,
        item_checks: list = None, max_items: "str | None" = None) -> list:
    ic = item_checks or []
    ename = _ext(scope_name, pfx)
    max_check = [] if max_items is None else [
        f"{_INDENT * 2}if (count_ >= {max_items}) {{ free(items_); return false; }}",
    ]
    return [
        f"static bool {fn_name}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        "{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, &(size_t){{ val_len_ }});",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}struct json_string *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}int next_;",
        f"{_INDENT}while ((next_ = json_arr_next(val_, &val_len_, &ait_, &av_, &alen_))"
        f" == JSON_NEXT_ITEM) {{",
    ] + max_check + [
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
        f"{_INDENT * 3}if (cap_ > nc_ || nc_ > SIZE_MAX / sizeof(*items_))"
        f" {{ free(items_); return false; }}",
        f"{_INDENT * 3}struct json_string *na_ = realloc(items_, nc_ * sizeof(*na_));",
        f"{_INDENT * 3}if (na_ == NULL) {{",
        f"{_INDENT * 4}free(items_);",
        f"{_INDENT * 4}return false;",
        f"{_INDENT * 3}}}",
        f"{_INDENT * 3}items_ = na_; cap_ = nc_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}if (!json_parse_string(av_, alen_, &items_[count_].str,"
        f" &items_[count_].len)) {{",
        f"{_INDENT * 3}free(items_);",
        f"{_INDENT * 3}return false;",
        f"{_INDENT * 2}}}",
    ] + ic + [
        f"{_INDENT * 2}count_++;",
        f"{_INDENT}}}",
        f"{_INDENT}if (next_ != JSON_NEXT_END) {{ free(items_); return false; }}",
        f"{_INDENT}for (; ait_ < val_len_; ait_++) {{",
        f"{_INDENT * 2}if (!json_iswhitespace(val_[ait_])) {{ free(items_); return false; }}",
        f"{_INDENT}}}",
        f"{_INDENT}/* duplicate key: release any previous allocation */",
        f"{_INDENT}free(obj->{fname});",
        f"{_INDENT}obj->{fname} = items_;",
        f"{_INDENT}obj->{_count_member(fname)} = count_;",
        f"{_INDENT}return true;",
        "}",
        "",
    ]


def _gen_unmarshal_array_object_helper(
        scope_name: str, pfx: str, fname: str, fn_name: str,
        child_scope: str, max_items: "str | None" = None) -> list:
    ename = _ext(scope_name, pfx)
    child_ename = _ext(child_scope, pfx)
    child_free = make_fn_name("free", child_scope, pfx)
    max_check = [] if max_items is None else [
        f"{_INDENT * 2}if (count_ >= {max_items}) {{ goto fail_; }}",
    ]
    return [
        f"static bool {fn_name}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        "{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, &(size_t){{ val_len_ }});",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}struct {child_ename} *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}int next_;",
        f"{_INDENT}while ((next_ = json_arr_next(val_, &val_len_, &ait_, &av_, &alen_))"
        f" == JSON_NEXT_ITEM) {{",
    ] + max_check + [
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
        f"{_INDENT * 3}if (cap_ > nc_ || nc_ > SIZE_MAX / sizeof(*items_))"
        f" {{ goto fail_; }}",
        f"{_INDENT * 3}struct {child_ename} *na_ = realloc(items_, nc_ * sizeof(*na_));",
        f"{_INDENT * 3}if (na_ == NULL) {{ goto fail_; }}",
        f"{_INDENT * 3}items_ = na_; cap_ = nc_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}if (!{make_fn_name('unmarshal', child_scope, pfx)}"
        f"(&items_[count_], av_, alen_)) {{",
        f"{_INDENT * 3}goto fail_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}count_++;",
        f"{_INDENT}}}",
        f"{_INDENT}if (next_ != JSON_NEXT_END) {{ goto fail_; }}",
        f"{_INDENT}for (; ait_ < val_len_; ait_++) {{",
        f"{_INDENT * 2}if (!json_iswhitespace(val_[ait_])) {{ goto fail_; }}",
        f"{_INDENT}}}",
        f"{_INDENT}/* duplicate key: release any previous allocation */",
        f"{_INDENT}if (obj->{fname} != NULL) {{",
        f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{_count_member(fname)}; i_++) {{",
        f"{_INDENT * 3}{child_free}(&obj->{fname}[i_]);",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}free(obj->{fname});",
        f"{_INDENT}}}",
        f"{_INDENT}obj->{fname} = items_;",
        f"{_INDENT}obj->{_count_member(fname)} = count_;",
        f"{_INDENT}return true;",
        "",
        "fail_:",
        f"{_INDENT}for (size_t i_ = 0; i_ < count_; i_++) {{",
        f"{_INDENT * 2}{child_free}(&items_[i_]);",
        f"{_INDENT}}}",
        f"{_INDENT}free(items_);",
        f"{_INDENT}return false;",
        "}",
        "",
    ]


def _gen_unmarshal_array_primitive_helper(
        scope_name: str, pfx: str, fname: str, fn_name: str, c_base: str,
        item_checks: list = None, max_items: "str | None" = None) -> list:
    ic = item_checks or []
    ename = _ext(scope_name, pfx)
    if c_base == "bool":
        parse_fn = "json_parse_bool"
    elif c_base == "int":
        parse_fn = "json_parse_int"
    elif c_base == "intmax_t":
        parse_fn = "json_parse_imax"
    elif c_base == "unsigned":
        parse_fn = "json_parse_uint"
    elif c_base == "uintmax_t":
        parse_fn = "json_parse_umax"
    else:  # double
        parse_fn = "json_parse_double"
    max_check = [] if max_items is None else [
        f"{_INDENT * 2}if (count_ >= {max_items}) {{ free(items_); return false; }}",
    ]
    return [
        f"static bool {fn_name}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        "{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, &(size_t){{ val_len_ }});",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}{c_base} *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}int next_;",
        f"{_INDENT}while ((next_ = json_arr_next(val_, &val_len_, &ait_, &av_, &alen_))"
        f" == JSON_NEXT_ITEM) {{",
    ] + max_check + [
        f"{_INDENT * 2}{c_base} pv_;",
        f"{_INDENT * 2}if (!{parse_fn}(av_, alen_, &pv_)) {{ free(items_); return false; }}",
    ] + ic + [
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
        f"{_INDENT * 3}if (cap_ > nc_ || nc_ > SIZE_MAX / sizeof(*items_))"
        f" {{ free(items_); return false; }}",
        f"{_INDENT * 3}{c_base} *na_ = realloc(items_, nc_ * sizeof(*na_));",
        f"{_INDENT * 3}if (na_ == NULL) {{ free(items_); return false; }}",
        f"{_INDENT * 3}items_ = na_; cap_ = nc_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}items_[count_++] = ({c_base})pv_;",
        f"{_INDENT}}}",
        f"{_INDENT}if (next_ != JSON_NEXT_END) {{ free(items_); return false; }}",
        f"{_INDENT}for (; ait_ < val_len_; ait_++) {{",
        f"{_INDENT * 2}if (!json_iswhitespace(val_[ait_])) {{ free(items_); return false; }}",
        f"{_INDENT}}}",
        f"{_INDENT}/* duplicate key: release any previous allocation */",
        f"{_INDENT}free(obj->{fname});",
        f"{_INDENT}obj->{fname} = items_;",
        f"{_INDENT}obj->{_count_member(fname)} = count_;",
        f"{_INDENT}return true;",
        "}",
        "",
    ]


def generate_unmarshal_c(
        scopes: list, pfx: str, schema_pfx: str, sub_schema: bool = False,
        validate: bool = True, strict: bool = False) -> list:
    """Generate a pull-parse unmarshal function for every scope.

    Design
    ------
    * Uses the pull-parse API: json_parse + json_obj_next to iterate object
      keys and dispatch to per-field handlers.
    * No callbacks, no context structs — a single while loop with a switch.
    * Nested object fields: call the child's unmarshal directly on the raw
      value fragment (modifying it in-place; the outer iterator has already
      advanced past that fragment).
    * Dynamic-key object fields: store (ptr, len) of the raw fragment,
      pointing into the caller's json buffer (zero-copy, NOT validated);
      the caller walks it later with json_parse + json_obj_next.
    * Array-of-string fields: parse the raw array fragment in-place, collect
      (ptr, len) pairs that point into the caller's json buffer; only the
      element table itself is heap-allocated.
    * Scalar string fields: parse the raw fragment in-place; obj->field
      is a json_string that points into the caller's json buffer.
    * Numeric/bool values: parse the raw fragment in-place.
    * Duplicate keys: last value wins; array/object fields release the
      previous allocation before storing the new one.
    * Failure: every error path funnels through a single fail_ label that
      releases partial allocations and resets *obj to all-zero, so callers
      may (but need not) call the free function after a failure.
    * ``strict``: unknown keys are rejected instead of skipped
      (additionalProperties: false semantics).
    """
    lines = []
    root_scope = scopes[0][0]
    scopes_map = {sn: (ks, nd) for sn, ks, nd in scopes}
    # The per-field array helpers share the <pfx>_unmarshal_... namespace with
    # the per-scope unmarshal functions, so hand the helper names out against
    # the whole schema's set of scope function names, not one scope's.
    reserved_fns = {
        make_fn_name("unmarshal", sn, pfx) for sn, _, _ in scopes}
    # Emit innermost scopes first so child unmarshal functions are defined
    # before any parent function that calls them.
    for scope_name, keys, node in reversed(scopes):
        ename = _ext(scope_name, pfx)
        required = _required_set(node)
        storage = "" if sub_schema or scope_name == root_scope else "static "
        fname_map = _make_field_map(keys, node)
        enum_const = _make_enum_const_map(keys, node, ename)
        arr_fn_map = _make_array_helper_map(
            scope_name, keys, node, pfx, fname_map, reserved_fns)

        # --- static helpers for array fields (emitted before the unmarshal function) ---
        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            kind = desc["kind"]
            fname = fname_map[key]
            max_items = prop.get("maxItems") \
                if validate and _is_array_kind(kind) else None
            if max_items is not None:
                # The in-loop guard compares a size_t, so a limit of 0 would
                # emit the always-true `count_ >= 0u` and one above UINT64_MAX
                # an unspellable literal -- both fatal under -Werror. Neither
                # is dropped silently: maxItems 0 becomes a post-parse
                # emptiness check below, and a limit no count can reach is
                # genuinely no limit.
                max_items = int(max_items)
                if max_items <= 0 or max_items > _UINT64_MAX:
                    max_items = None
                else:
                    max_items = _c_u64_literal(max_items)
            if kind == "array_string":
                item_checks = []
                if validate:
                    item_schema = prop.get("items", {})
                    if item_schema:
                        item_checks = _scalar_constraint_checks(
                            item_schema, "string", {
                                "kind": "string", "c_type": ""},
                            "items_[count_]", _INDENT * 2,
                            "free(items_); return false;", field=fname)
                lines += _gen_unmarshal_array_string_helper(
                    scope_name, pfx, fname, arr_fn_map[key], item_checks,
                    max_items)
            elif kind == "array_object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                lines += _gen_unmarshal_array_object_helper(
                    scope_name, pfx, fname, arr_fn_map[key], child_scope,
                    max_items)
            elif kind == "array_primitive":
                c_base = desc.get("c_base", "int")
                item_checks = []
                if validate:
                    item_schema = prop.get("items", {})
                    if item_schema:
                        item_desc = _infer_c_type(item_schema)
                        item_kind = item_desc["kind"]
                        if item_kind not in ("array_string", "array_object",
                                             "array_primitive", "object", "dynamic"):
                            item_checks = _scalar_constraint_checks(
                                item_schema, item_kind, item_desc, "pv_",
                                _INDENT * 2, "free(items_); return false;",
                                field=fname)
                lines += _gen_unmarshal_array_primitive_helper(
                    scope_name, pfx, fname, arr_fn_map[key], c_base,
                    item_checks, max_items)

        # Required-field tracking: one bit per required key, set when the key
        # is seen.  A bitmask (unlike a counter) is immune to duplicate keys.
        req_keys = [k for k in keys if k in required]
        req_bit = {k: i for i, k in enumerate(req_keys)}
        n_required = len(req_keys)
        if validate and n_required > 64:
            sys.exit(
                f"error: scope {scope_name!r} has {n_required} required "
                "properties; at most 64 are supported")

        # --- unmarshal function ---
        lines += [
            f"{storage}bool {make_fn_name('unmarshal', scope_name, pfx)}(",
            f"{_INDENT}struct {ename} *obj, char *json, size_t length)",
            "{",
        ]

        # --- zero-init + defaults via a single compound literal ---
        # Recursively collects defaults for nested object fields too: when a
        # child object key is absent from the input JSON the compound literal
        # ensures its fields receive the schema-defined default values.
        # Initializing *obj before any parsing keeps the failure path uniform:
        # every error goes through fail_, which releases partial allocations
        # and resets *obj to all-zero.
        designated = _collect_object_defaults(
            scope_name, schema_pfx, scopes_map)
        if designated:
            lines.append(f"{_INDENT}*obj = (struct {ename}){{")
            lines += designated
            lines.append(f"{_INDENT}}};")
        else:
            lines.append(f"{_INDENT}*obj = (struct {ename}){{ 0 }};")

        lines += [
            f"{_INDENT}const struct json_val root_ = json_parse(json, &(size_t){{ length }});",
            f"{_INDENT}if (root_.type != JSON_OBJECT) {{ goto fail_; }}",
            f"{_INDENT}json_iter iter_ = root_.iter;",
            f"{_INDENT}char *key_; size_t key_len_; char *val_; size_t val_len_;",
        ]
        if validate and n_required:
            lines.append(f"{_INDENT}uint_fast64_t required_ = 0;")
        lines += [
            f"{_INDENT}int next_;",
            "",
        ]

        lines += [
            f"{_INDENT}while ((next_ = json_obj_next(json, &length, &iter_,",
            f"{_INDENT * 3}&key_, &key_len_, &val_, &val_len_)) == JSON_NEXT_ITEM) {{",
            f"{_INDENT * 2}const int k_ = {_lookup_root(pfx, scope_name)}(key_, key_len_);",
            f"{_INDENT * 2}switch (k_) {{",
        ]

        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            kind = desc["kind"]
            fname = fname_map[key]
            enum_val = enum_const[key]
            seen_line = [
                f"{_INDENT * 3}required_ |= UINT64_C(1) << {req_bit[key]};",
            ] if validate and key in required else []

            lines.append(f"{_INDENT * 2}case {enum_val}: {{")
            if kind == "string":
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;", field=fname) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_string(val_, val_len_, &obj->{fname}.str,"
                    f" &obj->{fname}.len)) {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "int":
                c_type = desc.get("c_type", "intmax_t")
                fn = "json_parse_int" if c_type == "int" else "json_parse_imax"
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;", field=fname) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!{fn}(val_, val_len_, &obj->{fname})) {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "uint":
                c_type = desc.get("c_type", "uintmax_t")
                fn = "json_parse_uint" if c_type == "unsigned" else "json_parse_umax"
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;", field=fname) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!{fn}(val_, val_len_, &obj->{fname})) {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "double":
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;", field=fname) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_double(val_, val_len_, &obj->{fname}))"
                    f" {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "bool":
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;", field=fname) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_bool(val_, val_len_, &obj->{fname}))"
                    f" {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                lines += [
                    f"{_INDENT * 3}/* duplicate key: release the previous value first */",
                    f"{_INDENT * 3}{make_fn_name('free', child_scope, pfx)}(&obj->{fname});",
                    f"{_INDENT * 3}if (!{make_fn_name('unmarshal', child_scope, pfx)}"
                    f"(&obj->{fname}, val_, val_len_)) {{",
                    f"{_INDENT * 4}goto fail_;",
                    f"{_INDENT * 3}}}",
                ] + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "dynamic":
                lines += [
                    f"{_INDENT * 3}obj->{_json_member(fname)}.str = val_;",
                    f"{_INDENT * 3}obj->{_json_member(fname)}.len = val_len_;",
                ] + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind in ("array_string", "array_object", "array_primitive"):
                achks = []
                if validate:
                    # maxItems is enforced inside the helper loop (rejecting
                    # oversized input before it is fully buffered); only
                    # minItems needs a post-parse check -- plus maxItems 0,
                    # which has no in-loop form that survives -Wtype-limits.
                    min_items = prop.get("minItems")
                    if min_items is not None:
                        min_items = int(min_items)
                        if min_items > _UINT64_MAX:
                            achks.append(
                                f"{_INDENT * 3}goto fail_;"
                                " /* minItems exceeds any count */")
                        elif min_items > 0:
                            achks.append(
                                f"{_INDENT * 3}if (obj->{_count_member(fname)}"
                                f" < {min_items}u) {{ goto fail_; }}")
                    max_items = prop.get("maxItems")
                    if max_items is not None and int(max_items) <= 0:
                        achks.append(
                            f"{_INDENT * 3}if (obj->{_count_member(fname)} > 0u)"
                            f" {{ goto fail_; }}")
                arr_fn = arr_fn_map[key]
                lines += [
                    f"{_INDENT * 3}if (!{arr_fn}(obj, val_, val_len_)) {{ goto fail_; }}",
                ] + achks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            else:
                lines += [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]

        if strict:
            lines += [
                f"{_INDENT * 2}default:",
                f"{_INDENT * 3}/* unknown key rejected (--strict) */",
                f"{_INDENT * 3}goto fail_;",
                f"{_INDENT * 2}}}",
                f"{_INDENT}}}",
            ]
        else:
            lines += [
                f"{_INDENT * 2}default:",
                f"{_INDENT * 3}break;",
                f"{_INDENT * 2}}}",
                f"{_INDENT}}}",
            ]

        # The loop ends either at the closing '}' (JSON_NEXT_END) or on a
        # parse error / truncated input (JSON_NEXT_ERROR); only a clean end
        # is acceptable.
        lines.append(f"{_INDENT}if (next_ != JSON_NEXT_END) {{ goto fail_; }}")

        # Required field checks after the loop: every required key must have
        # set its bit.
        if validate and n_required:
            full_mask = (1 << n_required) - 1
            lines.append(
                f"{_INDENT}if (required_ != UINT64_C({hex(full_mask)})) {{ goto fail_; }}")

        lines += [
            f"{_INDENT}for (; iter_ < length; iter_++) {{",
            f"{_INDENT * 2}if (!json_iswhitespace(json[iter_])) {{ goto fail_; }}",
            f"{_INDENT}}}",
            f"{_INDENT}return true;",
            "",
            "fail_:",
            f"{_INDENT}{make_fn_name('free', scope_name, pfx)}(obj);",
            f"{_INDENT}*obj = (struct {ename}){{ 0 }};",
            f"{_INDENT}return false;",
            "}",
            "",
        ]

    return lines


def generate_marshal_c(
        scopes: list, pfx: str, schema_pfx: str, impl_names: dict,
        sub_schema: bool = False) -> list:
    """Generate marshal functions that write JSON text directly to a buffer.

    Each function uses snprintf semantics: returns the length required to
    encode *obj (excluding the terminating NUL) regardless of bufsz; the
    output is NUL-terminated whenever buf != NULL and bufsz > 0 and is
    truncated when the return value >= bufsz.  Returns -1 on error (e.g. a
    non-finite double, which has no JSON representation, or a length the
    public int return cannot represent).

    The running length is counted in size_t and converted to the public int
    return only at the outermost wrapper, by json_checked_int_ -- the same
    discipline json_marshal() follows with marshal_checked_int() in
    codec/json.c, so a document longer than INT_MAX yields -1 in both
    backends instead of an overflowing count.  SIZE_MAX is the internal
    error sentinel (again as in codec/json.c): every helper and macro that
    can fail returns it, each caller propagates it, and json_checked_int_
    maps it to -1 since it exceeds INT_MAX like any other unrepresentable
    count.

    The EMIT* macros compute ``buf + n_`` only while ``n_ < bufsz``; once
    the output is past the end of the buffer they pass NULL/0 instead, so
    no out-of-bounds pointer is ever formed (pointer arithmetic beyond
    one-past-the-end is undefined behavior even if never dereferenced).

    *impl_names* maps each scope to its file-local ``_impl`` helper's name,
    as _plan_identifiers assigned it.
    """
    # The character/literal/indent emitters are factored into small file-local
    # static helpers so each call site is a single call rather than an inlined
    # bounds-checked store (or, for indents, a copy loop), keeping the generated
    # source compact.  They carry no inline/noinline attribute: whether they are
    # inlined is the compiler's choice, and the output stays within ISO C.  Each
    # threads the running length counter through (in n_, out return value);
    # json_emit_str_ returns SIZE_MAX to signal an unrepresentable string.
    #
    # json_emit_str_ (wrapped by the EMIT_STR macro) is the one marshal helper
    # with a conditional caller: EMIT_STR is generated only for string and
    # array-of-string fields.  A schema whose whole object graph has no such
    # field would otherwise carry an unused file-local helper and trip
    # -Werror=unused-function, so gate the helper, its macro, and its #undef on
    # a string actually being present -- mirroring the <math.h>/isfinite gating
    # for double fields (_has_double_fields).
    needs_emit_str = _has_string_fields(scopes)
    str_helper = [
        "static size_t json_emit_str_(",
        f"{_INDENT}char *buf, size_t bufsz, size_t n_, const char *s, size_t len)",
        "{",
        f"{_INDENT}char *dst_ = (buf != NULL && n_ < bufsz) ? buf + n_ : NULL;",
        f"{_INDENT}const int r_ =",
        f"{_INDENT * 2}json_marshal_string(dst_, dst_ != NULL ? bufsz - n_ : 0, s, len);",
        f"{_INDENT}if (r_ < 0) {{ return SIZE_MAX; }}",
        f"{_INDENT}return json_add_(n_, (size_t)r_);",
        "}",
    ] if needs_emit_str else []
    # json_emit_double_ (wrapped by EMIT_DOUBLE) formats a double field or
    # array element.  C11 7.21.6.1 makes "%g" spell the radix with the
    # LC_NUMERIC decimal-point string, but JSON requires '.' (the runtime's
    # json_marshal emits it in every locale), so a program running under a
    # comma-decimal locale would otherwise get "1,5" -- not JSON, and the
    # comma is also the member separator.  The helper rewrites the radix
    # without asking the locale what it is (localeconv() is not thread-safe):
    # a finite "%g" is [-]digits[<radix>digits][e<sign>digits], so the run
    # between the integer digits and the next digit is the radix, whatever
    # its length.  Gated like json_emit_str_, on a double being present.
    needs_emit_double = _has_double_fields(scopes)
    double_helper = [
        "static size_t json_emit_double_(",
        f"{_INDENT}char *buf, size_t bufsz, size_t n_, double v)",
        "{",
        f"{_INDENT}/* JSON's radix is '.' whatever LC_NUMERIC spells it as */",
        f"{_INDENT}char tmp_[40];",
        f"{_INDENT}const int r_ = snprintf(tmp_, sizeof(tmp_), \"%.17g\", v);",
        f"{_INDENT}if (r_ < 0 || (size_t)r_ >= sizeof(tmp_)) {{ return SIZE_MAX; }}",
        f"{_INDENT}size_t len_ = (size_t)r_;",
        f"{_INDENT}size_t i_ = (tmp_[0] == '-') ? 1 : 0;",
        f"{_INDENT}while (i_ < len_ && tmp_[i_] >= '0' && tmp_[i_] <= '9') {{ i_++; }}",
        f"{_INDENT}if (i_ < len_ && tmp_[i_] != 'e') {{",
        f"{_INDENT * 2}size_t j_ = i_ + 1;",
        f"{_INDENT * 2}while (j_ < len_ && (tmp_[j_] < '0' || tmp_[j_] > '9')) {{ j_++; }}",
        f"{_INDENT * 2}tmp_[i_] = '.';",
        f"{_INDENT * 2}memmove(tmp_ + i_ + 1, tmp_ + j_, len_ - j_);",
        f"{_INDENT * 2}len_ -= j_ - i_ - 1;",
        f"{_INDENT}}}",
        f"{_INDENT}return json_emit_raw_(buf, bufsz, n_, tmp_, len_);",
        "}",
    ] if needs_emit_double else []
    double_macro = [
        "#define EMIT_DOUBLE(v) do { \\",
        f"{_INDENT}n_ = json_emit_double_(buf, bufsz, n_, (v)); \\",
        f"{_INDENT}if (n_ == SIZE_MAX) {{ return SIZE_MAX; }} \\",
        "} while (0)",
    ] if needs_emit_double else []
    str_macro = [
        "#define EMIT_STR(s, len) do { \\",
        f"{_INDENT}n_ = json_emit_str_(buf, bufsz, n_, (s), (len)); \\",
        f"{_INDENT}if (n_ == SIZE_MAX) {{ return SIZE_MAX; }} \\",
        "} while (0)",
    ] if needs_emit_str else []
    lines = [
        # Clamp the internal size_t count to the public snprintf-style int
        # return, treating an unrepresentable or error-sentinel (SIZE_MAX)
        # count as failure rather than silently wrapping.  The counterpart of
        # marshal_checked_int() in codec/json.c.
        "static int json_checked_int_(size_t n_)",
        "{",
        f"{_INDENT}if (n_ > (size_t)INT_MAX) {{ return -1; }}",
        f"{_INDENT}return (int)n_;",
        "}",
        # Saturate the running length to the SIZE_MAX error sentinel once the
        # total would exceed INT_MAX (the largest length the public int return
        # can represent) or wrap size_t; the emitters thread every addition
        # through here so the sentinel, once reached, sticks.  The counterpart
        # of json_add() in codec/json.c.
        "static size_t json_add_(size_t n_, size_t add_)",
        "{",
        f"{_INDENT}if (n_ > (size_t)INT_MAX || add_ > (size_t)INT_MAX - n_) {{"
        " return SIZE_MAX; }",
        f"{_INDENT}return n_ + add_;",
        "}",
        "static size_t json_emit_ch_(char *buf, size_t bufsz, size_t n_, char c)",
        "{",
        f"{_INDENT}if (buf != NULL && n_ < bufsz) {{ buf[n_] = c; }}",
        f"{_INDENT}return json_add_(n_, 1);",
        "}",
        "static size_t json_emit_raw_(",
        f"{_INDENT}char *buf, size_t bufsz, size_t n_, const char *s, size_t len)",
        "{",
        f"{_INDENT}if (buf != NULL && n_ < bufsz) {{",
        f"{_INDENT * 2}const size_t cap_ = bufsz - n_;",
        f"{_INDENT * 2}memcpy(buf + n_, s, len < cap_ ? len : cap_);",
        f"{_INDENT}}}",
        f"{_INDENT}return json_add_(n_, len);",
        "}",
    ] + str_helper + double_helper + [
        "static size_t json_emit_indent_(",
        f"{_INDENT}char *buf, size_t bufsz, size_t n_, const char *indent,",
        f"{_INDENT}size_t ind_len_, int d)",
        "{",
        f"{_INDENT}if (indent == NULL) {{ return n_; }}",
        f"{_INDENT}n_ = json_emit_ch_(buf, bufsz, n_, '\\n');",
        f"{_INDENT}for (int id_ = 0; id_ < d; id_++) {{",
        f"{_INDENT * 2}n_ = json_emit_raw_(buf, bufsz, n_, indent, ind_len_);",
        f"{_INDENT}}}",
        f"{_INDENT}return n_;",
        "}",
        "",
        # EMIT appends one character.
        "#define EMIT(c) do { n_ = json_emit_ch_(buf, bufsz, n_, (char)(c)); } while (0)",
        "#define EMITF(fmt, ...) do { \\",
        f"{_INDENT}char *dst_ = (buf != NULL && n_ < bufsz) ? buf + n_ : NULL; \\",
        f"{_INDENT}r_ = snprintf(dst_, dst_ != NULL ? bufsz - n_ : 0,"
        f" fmt, __VA_ARGS__); \\",
        f"{_INDENT}if (r_ < 0) {{ return SIZE_MAX; }} \\",
        f"{_INDENT}n_ = json_add_(n_, (size_t)r_); \\",
        "} while (0)",
    ] + str_macro + double_macro + [
        # The sub-object call returns a size_t count, so it needs its own
        # block-scope temporary rather than the int r_ that holds snprintf's
        # return in EMITF.
        "#define EMIT_SUB(fn, arg, d) do { \\",
        f"{_INDENT}char *dst_ = (buf != NULL && n_ < bufsz) ? buf + n_ : NULL; \\",
        f"{_INDENT}const size_t rsub_ ="
        f" (fn)(dst_, dst_ != NULL ? bufsz - n_ : 0, (arg), indent, (d)); \\",
        f"{_INDENT}if (rsub_ == SIZE_MAX) {{ return SIZE_MAX; }} \\",
        f"{_INDENT}n_ = json_add_(n_, rsub_); \\",
        "} while (0)",
        "#define EMIT_LIT(s) do { \\",
        f"{_INDENT}static const char lit_[] = s; \\",
        f"{_INDENT}n_ = json_emit_raw_(buf, bufsz, n_, lit_, sizeof(lit_) - 1); \\",
        "} while (0)",
        # EMIT_RAW writes a run of bytes verbatim, without JSON escaping and
        # with a length known only at run time; used for a dynamic field's
        # pre-serialized fragment.  EMIT_LIT is the compile-time counterpart.
        "#define EMIT_RAW(s, len) do { \\",
        f"{_INDENT}n_ = json_emit_raw_(buf, bufsz, n_, (s), (len)); \\",
        "} while (0)",
        # EMIT_INDENT writes a newline followed by (d) copies of the indent
        # string.  A NULL indent selects compact output: nothing is emitted.
        "#define EMIT_INDENT(d) do { \\",
        f"{_INDENT}n_ = json_emit_indent_(buf, bufsz, n_, indent, ind_len_, (d)); \\",
        "} while (0)",
        # EMIT_COLON writes the key/value separator: ':' compact, ': ' pretty.
        "#define EMIT_COLON() do { \\",
        f"{_INDENT}EMIT(':'); \\",
        f"{_INDENT}if (indent != NULL) {{ EMIT(' '); }} \\",
        "} while (0)",
        "",
    ]
    root_scope = scopes[0][0]
    scope_node_map = {sn: (ks, nd) for sn, ks, nd in scopes}
    # Emit innermost scopes first (consistent with free/unmarshal) so child
    # helpers are defined before any parent function that calls them.
    for scope_name, keys, node in reversed(scopes):
        ename = _ext(scope_name, pfx)
        required = _required_set(node)
        is_public = sub_schema or scope_name == root_scope
        fname_map = _make_field_map(keys, node)
        impl_name = impl_names[scope_name]

        # Collect the fields that actually emit output, so we can insert
        # commas between them correctly.
        emit_fields = []
        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            kind = desc["kind"]
            fname = fname_map[key]
            is_req = key in required
            if kind == "string":
                emit_fields.append(("string", fname, key, is_req))
            elif kind in ("int", "uint", "double"):
                emit_fields.append((kind, fname, key, is_req))
            elif kind == "bool":
                emit_fields.append(("bool", fname, key, is_req))
            elif kind == "object":
                emit_fields.append(("object", fname, key, is_req))
            elif kind == "dynamic":
                emit_fields.append(("dynamic", fname, key, is_req))
            elif kind == "array_string":
                emit_fields.append(("array_string", fname, key, is_req))
            elif kind in ("array_object", "array_primitive"):
                emit_fields.append((kind, fname, key, is_req))

        # The impl counts in size_t and reports failure as SIZE_MAX; only the
        # public wrapper below narrows to the snprintf-style int.
        lines += [
            f"static size_t {impl_name}(",
            f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj,",
            f"{_INDENT}const char *indent, int depth)",
            "{",
            f"{_INDENT}size_t n_ = 0;",
            f"{_INDENT}int r_ = 0;",
            f"{_INDENT}(void)r_;",
            f"{_INDENT}const size_t ind_len_ = (indent != NULL) ? strlen(indent) : 0;",
            f"{_INDENT}(void)ind_len_;",
            f"{_INDENT}(void)depth;",
            "",
        ]

        # Opening brace; record n_ after '{' for trailing-comma removal.
        lines += [
            f"{_INDENT}EMIT('{{');",
            f"{_INDENT}const size_t n_start_ = n_;",
            "",
        ]

        for kind, fname, json_key, is_req in emit_fields:
            esc_key = _c_string_literal(_json_escape(json_key))[0]
            if kind == "todo":
                lines += [
                    f"{_INDENT}/* TODO: {fname} marshal not yet generated */",
                ]
                continue

            # Determine the condition under which this field is emitted.
            # Scalar types (bool/int/uint/double) have no NULL sentinel, so
            # they are always emitted regardless of value.
            # String/array/dynamic fields use NULL to represent "not present",
            # but only while optional: a required field always emits, filling a
            # NULL with the empty form of its type (see the value blocks below).
            # Object fields: required ones are always emitted; optional ones
            # use the first required string sub-field as a presence sentinel —
            # the same NULL-as-absent convention as strings.
            if kind == "string":
                cond = None if is_req else f"obj->{fname}.str != NULL"
            elif kind in ("bool", "int", "uint", "double"):
                cond = None
            elif kind == "object":
                if is_req:
                    cond = None
                else:
                    child_scope_name = _scope_of_child(
                        _path_from_scope(scope_name, schema_pfx), json_key, schema_pfx)
                    child_entry = scope_node_map.get(child_scope_name)
                    if child_entry is not None:
                        child_keys, child_node = child_entry
                        child_req = _required_set(child_node)
                        child_fmap = _make_field_map(child_keys, child_node)
                        sentinel = next(
                            (child_fmap[k] for k in child_keys
                             if k in child_req and
                             _infer_c_type(child_node["properties"][k])["kind"] == "string"),
                            None)
                        cond = f"obj->{fname}.{sentinel}.str != NULL" if sentinel else None
                    else:
                        cond = None
            elif kind == "dynamic":
                cond = None if is_req else f"obj->{_json_member(fname)}.str != NULL"
            elif kind in ("array_string", "array_object", "array_primitive"):
                if is_req:
                    cond = None
                else:
                    cond = f"obj->{fname} != NULL"
            else:
                cond = None

            # Build the block that emits this field using EMIT / EMIT_STR /
            # EMIT_SUB macros defined at the top of the marshal section.
            # Every path appends a trailing ','; the closing-brace block
            # strips the last one before emitting '}'.  Each field begins on
            # its own indented line (EMIT_INDENT, a no-op in compact mode) and
            # uses EMIT_COLON for the key/value separator (': ' when pretty).
            field_lines = []

            # Shared "<newline+indent>"key":<sep>" prefix for the field.
            key_prefix = [
                f"{_INDENT * 2}EMIT_INDENT(depth + 1);",
                f"{_INDENT * 2}EMIT('\"');",
                f"{_INDENT * 2}EMIT_LIT(\"{esc_key}\");",
                f"{_INDENT * 2}EMIT('\"');",
                f"{_INDENT * 2}EMIT_COLON();",
            ]

            if kind == "string":
                emit_str = f"EMIT_STR(obj->{fname}.str, obj->{fname}.len);"
                if is_req:
                    # forced out by .required: "" keeps the declared string
                    # type, which a bare null would not
                    value_lines = [
                        f"{_INDENT * 2}if (obj->{fname}.str != NULL) {{",
                        f"{_INDENT * 3}{emit_str}",
                        f"{_INDENT * 2}}} else {{",
                        f'{_INDENT * 3}EMIT_LIT("\\"\\"");',
                        f"{_INDENT * 2}}}",
                    ]
                else:
                    value_lines = [f"{_INDENT * 2}{emit_str}"]
                field_lines += key_prefix + value_lines + [
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "int":
                pdesc = _infer_c_type(node["properties"][json_key])
                if pdesc.get("c_type") == "int":
                    emitf_line = f"{_INDENT * 2}EMITF(\"%d\", obj->{fname});"
                else:
                    emitf_line = f"{_INDENT * 2}EMITF(\"%jd\", (intmax_t)obj->{fname});"
                field_lines += key_prefix + [
                    emitf_line,
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "uint":
                pdesc = _infer_c_type(node["properties"][json_key])
                if pdesc.get("c_type") == "unsigned":
                    emitf_line = f"{_INDENT * 2}EMITF(\"%u\", obj->{fname});"
                else:
                    emitf_line = f"{_INDENT * 2}EMITF(\"%ju\", (uintmax_t)obj->{fname});"
                field_lines += key_prefix + [
                    emitf_line,
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "double":
                field_lines += [
                    f"{_INDENT * 2}/* NaN/Inf have no JSON representation */",
                    f"{_INDENT * 2}if (!isfinite(obj->{fname})) {{ return SIZE_MAX; }}",
                ] + key_prefix + [
                    f"{_INDENT * 2}EMIT_DOUBLE(obj->{fname});",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "bool":
                field_lines += key_prefix + [
                    f"{_INDENT * 2}if (obj->{fname}) {{",
                    f"{_INDENT * 3}EMIT_LIT(\"true\");",
                    f"{_INDENT * 2}}} else {{",
                    f"{_INDENT * 3}EMIT_LIT(\"false\");",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), json_key, schema_pfx)
                child_impl = impl_names[child_scope]
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT_SUB({child_impl}, &obj->{fname}, depth + 1);",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "dynamic":
                # a memcpy of the fragment, not snprintf("%.*s"): the latter
                # would narrow the size_t length to int for the precision and
                # stop at an embedded NUL, where the table backend copies
                # straight through.
                emit_dyn = (f"EMIT_RAW(obj->{_json_member(fname)}.str,"
                            f" obj->{_json_member(fname)}.len);")
                if is_req:
                    # forced out by .required: a raw fragment has no empty
                    # form, so absent becomes null
                    value_lines = [
                        f"{_INDENT * 2}if (obj->{_json_member(fname)}.str != NULL) {{",
                        f"{_INDENT * 3}{emit_dyn}",
                        f"{_INDENT * 2}}} else {{",
                        f'{_INDENT * 3}EMIT_LIT("null");',
                        f"{_INDENT * 2}}}",
                    ]
                else:
                    value_lines = [f"{_INDENT * 2}{emit_dyn}"]
                field_lines += key_prefix + value_lines + [
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "array_string":
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT('[');",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{_count_member(fname)}; i_++) {{",
                    f"{_INDENT * 3}if (i_ > 0) EMIT(',');",
                    f"{_INDENT * 3}EMIT_INDENT(depth + 2);",
                    f"{_INDENT * 3}EMIT_STR(obj->{fname}[i_].str, obj->{fname}[i_].len);",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}if (obj->{_count_member(fname)} > 0) {{ EMIT_INDENT(depth + 1); }}",
                    f"{_INDENT * 2}EMIT(']');",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "array_object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), json_key, schema_pfx)
                child_impl = impl_names[child_scope]
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT('[');",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{_count_member(fname)}; i_++) {{",
                    f"{_INDENT * 3}if (i_ > 0) EMIT(',');",
                    f"{_INDENT * 3}EMIT_INDENT(depth + 2);",
                    f"{_INDENT * 3}EMIT_SUB({child_impl}, &obj->{fname}[i_], depth + 2);",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}if (obj->{_count_member(fname)} > 0) {{ EMIT_INDENT(depth + 1); }}",
                    f"{_INDENT * 2}EMIT(']');",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "array_primitive":
                prop_schema = node["properties"][json_key]
                prim_desc = _infer_c_type(prop_schema)
                c_base = prim_desc.get("c_base", "int")
                if c_base == "bool":
                    elem_lines = [
                        f"{_INDENT * 3}if (i_ > 0) EMIT(',');",
                        f"{_INDENT * 3}EMIT_INDENT(depth + 2);",
                        f"{_INDENT * 3}if (obj->{fname}[i_]) {{",
                        f"{_INDENT * 4}EMIT_LIT(\"true\");",
                        f"{_INDENT * 3}}} else {{",
                        f"{_INDENT * 4}EMIT_LIT(\"false\");",
                        f"{_INDENT * 3}}}",
                    ]
                else:
                    fmt = {"int": "%d", "intmax_t": "%jd",
                           "unsigned": "%u", "uintmax_t": "%ju"}.get(c_base)
                    elem_lines = [
                        f"{_INDENT * 3}if (i_ > 0) EMIT(',');",
                        f"{_INDENT * 3}EMIT_INDENT(depth + 2);",
                    ]
                    if c_base == "double":
                        elem_lines += [
                            f"{_INDENT * 3}/* NaN/Inf have no JSON representation */",
                            f"{_INDENT * 3}if (!isfinite(obj->{fname}[i_])) {{ return SIZE_MAX; }}",
                        ]
                    elem_lines += [
                        f"{_INDENT * 3}EMIT_DOUBLE(obj->{fname}[i_]);"
                        if c_base == "double" else
                        f"{_INDENT * 3}EMITF(\"{fmt}\", obj->{fname}[i_]);",
                    ]
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT('[');",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{_count_member(fname)}; i_++) {{",
                ] + elem_lines + [
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}if (obj->{_count_member(fname)} > 0) {{ EMIT_INDENT(depth + 1); }}",
                    f"{_INDENT * 2}EMIT(']');",
                    f"{_INDENT * 2}EMIT(',');",
                ]

            # Wrap in condition if needed
            if cond is not None:
                lines.append(f"{_INDENT}if ({cond}) {{")
                lines += field_lines
                lines.append(f"{_INDENT}}}")
            else:
                # Always emit — strip leading indentation
                for fl in field_lines:
                    lines.append(fl[len(_INDENT):]
                                 if fl.startswith(_INDENT) else fl)

        # Closing brace: when any field was emitted, drop its trailing comma and
        # break '}' onto its own line at this object's level (EMIT_INDENT is a
        # no-op in compact mode; an empty object stays "{}").  Then NUL-terminate
        # (snprintf semantics); nested EMIT_SUB calls also write a NUL, but the
        # parent's next EMIT overwrites it, so the outermost terminator lands last.
        lines += [
            "",
            f"{_INDENT}if (n_ > n_start_) {{",
            f"{_INDENT * 2}n_--;",
            f"{_INDENT * 2}EMIT_INDENT(depth);",
            f"{_INDENT}}}",
            f"{_INDENT}EMIT('}}');",
            f"{_INDENT}if (buf != NULL && bufsz > 0) {{",
            f"{_INDENT * 2}buf[n_ < bufsz ? n_ : bufsz - 1] = '\\0';",
            f"{_INDENT}}}",
            "",
            f"{_INDENT}return n_;",
            "}",
            "",
        ]

        # Public entry point: a thin wrapper that starts recursion at depth 0
        # and narrows the size_t count to the public int return.  The
        # depth/recursion bookkeeping is kept out of the public signature,
        # which exposes only the indent string (NULL selects compact output).
        if is_public:
            storage = "" if sub_schema or scope_name == root_scope else "static "
            lines += [
                f"{storage}int {make_fn_name('marshal', scope_name, pfx)}(",
                f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj,",
                f"{_INDENT}const char *indent)",
                "{",
                f"{_INDENT}return json_checked_int_(",
                f"{_INDENT * 2}{impl_name}(buf, bufsz, obj, indent, 0));",
                "}",
                "",
            ]
    lines += [
        "",
        "#undef EMIT",
        "#undef EMITF",
    ] + (["#undef EMIT_STR"] if needs_emit_str else []) + (
        ["#undef EMIT_DOUBLE"] if needs_emit_double else []) + [
        "#undef EMIT_SUB",
        "#undef EMIT_LIT",
        "#undef EMIT_RAW",
        "#undef EMIT_INDENT",
        "#undef EMIT_COLON",
        "",
    ]
    return lines


def generate_free_c(scopes: list, pfx: str, schema_pfx: str, sub_schema: bool = False) -> list:
    """Return source lines defining the ``free`` functions."""
    lines = []
    root_scope = scopes[0][0]
    # emit in reverse order: innermost first (needed if parent calls child free)
    for scope_name, keys, node in reversed(scopes):
        ename = _ext(scope_name, pfx)
        storage = "" if sub_schema or scope_name == root_scope else "static "
        fname_map = _make_field_map(keys, node)
        lines.append(
            f"{storage}void {make_fn_name('free', scope_name, pfx)}(struct {ename} *obj)")
        lines.append("{")
        has_body = False
        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            kind = desc["kind"]
            fname = fname_map[key]
            if kind == "object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                lines.append(
                    f"{_INDENT}{make_fn_name('free', child_scope, pfx)}(&obj->{fname});")
                has_body = True
            elif kind == "array_string":
                lines.append(f"{_INDENT}free(obj->{fname});")
                has_body = True
            elif kind == "array_object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                lines.append(f"{_INDENT}if (obj->{fname} != NULL) {{")
                lines.append(
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{_count_member(fname)}; i_++) {{")
                lines.append(
                    f"{_INDENT * 3}{make_fn_name('free', child_scope, pfx)}(&obj->{fname}[i_]);")
                lines.append(f"{_INDENT * 2}}}")
                lines.append(f"{_INDENT * 2}free(obj->{fname});")
                lines.append(f"{_INDENT}}}")
                has_body = True
            elif kind == "array_primitive":
                lines.append(f"{_INDENT}free(obj->{fname});")
                has_body = True
        if not has_body:
            lines.append(f"{_INDENT}(void)obj;")
        lines.append("}")
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Table-driven descriptor generation
# ---------------------------------------------------------------------------

def _check_literal_range(n: int, c_type: str, lo: int, hi: int) -> None:
    """Refuse a constraint value the target C type cannot hold.

    Outside the widest integer type's range the value has no C literal form at
    all and the compiler rejects the source.  Outside a narrow type's range it
    is worse: a literal exists and compiles, but denotes another value
    entirely (``-1u`` is ``-(1u)``, i.e. UINT_MAX), so the constraint silently
    stops meaning what the schema said.  A bound that constrains nothing for
    the type is dropped by the caller long before reaching here, so anything
    that arrives out of range is a value the schema states as significant,
    which makes silently clamping or dropping it wrong.  A schema constraint
    is screened against this same table before it gets here, though -- a
    const/enum member by _filter_const_values, a bound by
    _check_bound_satisfiable -- so what still arrives out of range is an
    unrepresentable ``default``.
    """
    if lo <= n <= hi:
        return
    sys.exit(
        f"error: constraint value {n} lies outside the range of the "
        f"generated field type {c_type} ([{lo}, {hi}]) and cannot be spelled "
        "as a C literal of that type; widen or remove the constraint")


def _c_num_literal(val: "int | float", kind: str, c_type: str) -> str:
    """Format a numeric schema constraint value as a C literal matching c_type.

    The most negative value of a signed type has no literal form in C: the
    source ``-9223372036854775808`` is unary minus applied to the constant
    9223372036854775808, which exceeds INTMAX_MAX and is rejected ("integer
    constant is so large that it is unsigned").  It is spelled as one less
    than the negated maximum instead, which is how <stdint.h> itself defines
    INT64_MIN.

    Every integer type is range-checked, the narrow ones no less than the wide
    ones: an out-of-range value on ``unsigned`` has a C literal form that
    compiles but does not mean what the schema said -- ``-1u`` is ``-(1u)``,
    i.e. UINT_MAX -- which would turn a bound into one the schema never stated
    and an unrepresentable default into a silently different value.  The ranges
    come from _C_TYPE_RANGE, the same table the callers use to drop a bound
    that constrains nothing for the type, so a value can be dropped as vacuous
    or rejected as unspellable but never both.  Schema constraint values are
    screened against that table earlier, each for what it actually is: an
    unmatchable const/enum member by _filter_const_values, an unsatisfiable
    bound by _check_bound_satisfiable, and an out-of-range multipleOf not at
    all -- a narrow field still satisfies that divisor at 0, so the check is
    widened rather than refused, and the literal is asked for in the wider
    type.
    """
    if kind in ("int", "uint"):
        n = int(val)
        # An unknown c_type keeps the unbounded range _C_TYPE_RANGE's other
        # users give it, so the check never fires on a type it cannot judge.
        type_min, type_max = _C_TYPE_RANGE.get(
            c_type, (float("-inf"), float("inf")))
        _check_literal_range(n, c_type, type_min, type_max)
        if c_type == "intmax_t":
            if n == _INT64_MIN:
                return f"(-INTMAX_C({_INT64_MAX}) - 1)"
            return f"INTMAX_C({n})"
        if c_type == "uintmax_t":
            return f"UINTMAX_C({n})"
        if c_type == "unsigned":
            return f"{n}u"
        if n == _INT32_MIN:
            return f"(-{_INT32_MAX} - 1)"
        return str(n)
    # double
    # The json module keeps an integer-spelled number exact however large it
    # is, so it is screened for the double range as well: one beyond it has
    # no finite double value and would be emitted as a floating constant the
    # compiler rejects as out of range.
    try:
        fval = float(val)
    except OverflowError:
        fval = math.inf
    if not math.isfinite(fval):
        sys.exit(
            f"error: numeric value {val!r} has no finite double value and "
            f"cannot be emitted as a portable C literal (JSON numbers must be "
            f"finite)")
    if isinstance(val, int):
        return f"{val}.0"
    return repr(fval)


def _kind_const(desc: dict) -> str:
    """Return the JSON_K_* element-kind constant for a property descriptor."""
    kind = desc["kind"]
    if kind in ("string", "array_string"):
        return "JSON_K_STRING"
    if kind == "int":
        return "JSON_K_INT" if desc.get("c_type") == "int" else "JSON_K_IMAX"
    if kind == "uint":
        return ("JSON_K_UINT" if desc.get("c_type") == "unsigned"
                else "JSON_K_UMAX")
    if kind == "double":
        return "JSON_K_DOUBLE"
    if kind == "bool":
        return "JSON_K_BOOL"
    if kind in ("object", "array_object"):
        return "JSON_K_OBJECT"
    if kind == "dynamic":
        return "JSON_K_DYNAMIC"
    if kind == "array_primitive":
        return {
            "int": "JSON_K_INT", "intmax_t": "JSON_K_IMAX",
            "unsigned": "JSON_K_UINT", "uintmax_t": "JSON_K_UMAX",
            "double": "JSON_K_DOUBLE", "bool": "JSON_K_BOOL",
        }[desc.get("c_base", "intmax_t")]
    return "JSON_K_DYNAMIC"


def _is_array_kind(kind: str) -> bool:
    return kind in ("array_string", "array_object", "array_primitive")


def _build_constraint_c(
        ename: str, fname: str, value_kind: "str | None", value_schema: dict,
        array_schema: "dict | None", plan: _IdentPlan) -> tuple:
    """Return (cvar_name or None, [c_lines]) for a field's constraints.

    Emits a ``static const struct json_constraint`` plus any enum/const side
    arrays, each named through *plan* (see _IdentPlan.table).  ``value_kind`` is the element kind (string/int/uint/double/bool,
    or None for object arrays).  ``array_schema``, when given, contributes
    minItems/maxItems.  Mirrors the bound tightening of the former
    _scalar_constraint_checks so the encoded data matches the old inline checks.
    """
    flags: list = []
    members: list = []  # struct-level designated members (min_items, ...)
    union: list = []  # the active union member, ".X = { ... }"
    side: list = []  # enum side-array definitions, emitted before the struct

    array_min_expr = None
    array_max_expr = None
    array_bounds_impossible = False
    if array_schema is not None:
        mn = array_schema.get("minItems")
        mx = array_schema.get("maxItems")
        if mn is not None:
            mn = int(mn)
            if mn > _UINT64_MAX:
                array_bounds_impossible = True
            elif mn > 0:
                mlit = _c_u64_literal(mn)
                # A lower bound above SIZE_MAX is unsatisfiable on the
                # target.  Keep the check in the descriptor and pair it with
                # max_items == 0 on such targets so even an empty array fails.
                flags.append("JSON_C_MIN_ITEMS")
                flags.append(
                    f"(JSON_C_MAX_ITEMS * ({mlit} > SIZE_MAX))")
                array_min_expr = (
                    f"(({mlit} <= SIZE_MAX) ? (size_t){mlit} : SIZE_MAX)")
        if mx is not None:
            mx = int(mx)
            if mx <= _UINT64_MAX:
                mlit = _c_u64_literal(mx)
                flags.append(
                    f"(JSON_C_MAX_ITEMS * ({mlit} <= SIZE_MAX))")
                array_max_expr = (
                    f"(({mlit} <= SIZE_MAX) ? (size_t){mlit} : 0)")
        if array_bounds_impossible:
            flags = ["JSON_C_MIN_ITEMS", "JSON_C_MAX_ITEMS"]
            array_min_expr = "SIZE_MAX"
            array_max_expr = "0"
        if array_min_expr is not None:
            members.append(f"{_INDENT}.min_items = {array_min_expr},")
        if array_max_expr is not None:
            members.append(f"{_INDENT}.max_items = {array_max_expr},")

    if value_kind == "string":
        um = []
        string_bounds_impossible = False
        mn = value_schema.get("minLength")
        mx = value_schema.get("maxLength")
        if mn is not None:
            mn = int(mn)
            if mn > _UINT64_MAX:
                string_bounds_impossible = True
            elif mn > 0:
                mlit = _c_u64_literal(mn)
                flags.append("JSON_C_MIN_LEN")
                flags.append(f"(JSON_C_MAX_LEN * ({mlit} > SIZE_MAX))")
                um.append(
                    f".min_len = (({mlit} <= SIZE_MAX) ? "
                    f"(size_t){mlit} : SIZE_MAX)")
        if mx is not None:
            mx = int(mx)
            if mx <= _UINT64_MAX:
                mlit = _c_u64_literal(mx)
                flags.append(f"(JSON_C_MAX_LEN * ({mlit} <= SIZE_MAX))")
                um.append(
                    f".max_len = (({mlit} <= SIZE_MAX) ? "
                    f"(size_t){mlit} : 0)")
        if string_bounds_impossible:
            flags = [flag for flag in flags
                     if not (flag.startswith("JSON_C_MIN_LEN") or
                             flag.startswith("JSON_C_MAX_LEN") or
                             flag.startswith("(JSON_C_MAX_LEN"))]
            flags += ["JSON_C_MIN_LEN", "JSON_C_MAX_LEN"]
            um = [".min_len = SIZE_MAX", ".max_len = 0"]
        const_v = value_schema.get("const", _MISSING)
        if const_v is not _MISSING:
            _filter_const_values([const_v], "string", fname, "const")
            flags.append("JSON_C_CONST")
            esc, blen = _c_string_literal(str(const_v))
            um.append(f'.konst = {{ .len = {blen}, .str = "{esc}" }}')
        enum_vs = value_schema.get("enum")
        if enum_vs is not None:
            enum_vs = _filter_const_values(enum_vs, "string", fname, "enum")
            flags.append("JSON_C_ENUM")
            arr = plan.table(_join_ident(ename, fname, "enum"))
            side.append(f"static const struct json_string {arr}[] = {{")
            for v in enum_vs:
                esc, blen = _c_string_literal(str(v))
                side.append(f'{_INDENT}{{ .len = {blen}, .str = "{esc}" }},')
            side.append("};")
            um.append(f".enums = {arr}")
            um.append(f".n_enum = {len(enum_vs)}")
        if um:
            union.append(f"{_INDENT}.str = {{ " + ", ".join(um) + " },")

    elif value_kind in ("int", "uint"):
        is_unsigned = value_kind == "uint"
        suf = "u" if is_unsigned else "i"
        wide = "uintmax_t" if is_unsigned else "intmax_t"
        klit = "uint" if is_unsigned else "int"
        # The descriptor stores every numeric constraint in the wide type, so
        # that is what the literals are spelled in; whether a const/enum value
        # can ever match is judged against the field's own C type instead, the
        # way the function backend judges it, or the two backends would differ
        # on which schemas are generatable.
        field_c_type = _infer_c_type(value_schema).get("c_type", wide)

        def lit(v):
            return _c_num_literal(int(v), klit, wide)

        minimum = value_schema.get("minimum")
        maximum = value_schema.get("maximum")
        excl_min = value_schema.get("exclusiveMinimum")
        excl_max = value_schema.get("exclusiveMaximum")
        mult_of = value_schema.get("multipleOf")
        const_v = value_schema.get("const", _MISSING)
        enum_vs = value_schema.get("enum")
        if minimum is not None:
            minimum = math.ceil(minimum)
        if maximum is not None:
            maximum = math.floor(maximum)
        if excl_min is not None and excl_min != math.floor(excl_min):
            nm = math.ceil(excl_min)
            minimum = nm if minimum is None else max(minimum, nm)
            excl_min = None
        if excl_max is not None and excl_max != math.floor(excl_max):
            nm = math.floor(excl_max)
            maximum = nm if maximum is None else min(maximum, nm)
            excl_max = None
        # Drop a bound that is always true for the width the table stores it
        # in, exactly as the function backend does via _C_TYPE_RANGE: no
        # uintmax_t is below 0 and none exceeds UINT64_MAX, so keeping such a
        # bound would at best waste a comparison and at worst -- above
        # INT64_MAX for the signed union member -- ask for a literal that
        # cannot be spelled.
        type_min, type_max = (0, _UINT64_MAX) if is_unsigned else \
            (_INT64_MIN, _INT64_MAX)
        # A bound that survives is judged against the field's own C type, the
        # way the function backend judges it: the table stores it widened, but
        # the instance it is compared with can only ever hold the narrow type,
        # so a bound outside that range excludes every instance and makes the
        # schema unsatisfiable rather than merely wide.
        um = []
        if minimum is not None and minimum > type_min:
            _check_bound_satisfiable(minimum, "minimum", fname, field_c_type)
            flags.append("JSON_C_MIN")
            um.append(f".min = {lit(minimum)}")
        if maximum is not None and maximum < type_max:
            _check_bound_satisfiable(maximum, "maximum", fname, field_c_type)
            flags.append("JSON_C_MAX")
            um.append(f".max = {lit(maximum)}")
        if excl_min is not None and excl_min >= type_min:
            _check_bound_satisfiable(
                excl_min, "exclusiveMinimum", fname, field_c_type)
            flags.append("JSON_C_EXCL_MIN")
            um.append(f".excl_min = {lit(excl_min)}")
        if excl_max is not None and excl_max <= type_max:
            _check_bound_satisfiable(
                excl_max, "exclusiveMaximum", fname, field_c_type)
            flags.append("JSON_C_EXCL_MAX")
            um.append(f".excl_max = {lit(excl_max)}")
        if mult_of is not None:
            if mult_of <= 0 or mult_of != math.floor(mult_of):
                print(
                    f"  warning: non-integral or non-positive multipleOf "
                    f"{mult_of!r} on an integer field is not supported; "
                    f"the check is omitted", file=sys.stderr)
            else:
                flags.append("JSON_C_MULT")
                um.append(f".mult = {lit(mult_of)}")
        if const_v is not _MISSING:
            _filter_const_values(
                [const_v], value_kind, fname, "const", field_c_type)
            flags.append("JSON_C_CONST")
            um.append(f".konst = {lit(const_v)}")
        if enum_vs is not None:
            enum_vs = _filter_const_values(
                enum_vs, value_kind, fname, "enum", field_c_type)
            flags.append("JSON_C_ENUM")
            arr = plan.table(_join_ident(ename, fname, "enum"))
            side.append(f"static const {wide} {arr}[] = {{")
            side.append(f"{_INDENT}" + ", ".join(lit(v)
                        for v in enum_vs) + ",")
            side.append("};")
            um.append(f".enums = {arr}")
            um.append(f".n_enum = {len(enum_vs)}")
        if um:
            union.append(f"{_INDENT}.{suf} = {{ " + ", ".join(um) + " },")

    elif value_kind == "double":
        def dlit(v):
            return _c_num_literal(v, "double", "")

        minimum = value_schema.get("minimum")
        maximum = value_schema.get("maximum")
        excl_min = value_schema.get("exclusiveMinimum")
        excl_max = value_schema.get("exclusiveMaximum")
        mult_of = value_schema.get("multipleOf")
        const_v = value_schema.get("const", _MISSING)
        enum_vs = value_schema.get("enum")
        um = []
        if minimum is not None:
            flags.append("JSON_C_MIN")
            um.append(f".min = {dlit(minimum)}")
        if maximum is not None:
            flags.append("JSON_C_MAX")
            um.append(f".max = {dlit(maximum)}")
        if excl_min is not None:
            flags.append("JSON_C_EXCL_MIN")
            um.append(f".excl_min = {dlit(excl_min)}")
        if excl_max is not None:
            flags.append("JSON_C_EXCL_MAX")
            um.append(f".excl_max = {dlit(excl_max)}")
        if mult_of is not None:
            if mult_of <= 0:
                print(
                    f"  warning: non-positive multipleOf {mult_of!r} on a "
                    f"number field is not supported; the check is omitted",
                    file=sys.stderr)
            else:
                flags.append("JSON_C_MULT")
                um.append(f".mult = {dlit(mult_of)}")
        if const_v is not _MISSING:
            _filter_const_values([const_v], "double", fname, "const")
            flags.append("JSON_C_CONST")
            um.append(f".konst = {dlit(const_v)}")
        if enum_vs is not None:
            enum_vs = _filter_const_values(enum_vs, "double", fname, "enum")
            flags.append("JSON_C_ENUM")
            arr = plan.table(_join_ident(ename, fname, "enum"))
            side.append(f"static const double {arr}[] = {{")
            side.append(
                f"{_INDENT}" + ", ".join(dlit(v) for v in enum_vs) + ",")
            side.append("};")
            um.append(f".enums = {arr}")
            um.append(f".n_enum = {len(enum_vs)}")
        if um:
            union.append(f"{_INDENT}.d = {{ " + ", ".join(um) + " },")

    elif value_kind == "bool":
        const_v = value_schema.get("const", _MISSING)
        enum_vs = value_schema.get("enum")
        bval = None
        if const_v is not _MISSING:
            _filter_const_values([const_v], "bool", fname, "const")
            bval = const_v
        if enum_vs is not None:
            kept = _filter_const_values(enum_vs, "bool", fname, "enum")
            vals = set(kept)
            if const_v is not _MISSING and const_v not in vals:
                sys.exit(
                    f"error: field {fname!r}: boolean const is not in enum; "
                    "the constraints are unsatisfiable")
            if len(vals) == 1:
                bval = next(iter(vals))
        if bval is not None:
            flags.append("JSON_C_CONST")
            union.append(f"{_INDENT}.b = {{ .konst = {1 if bval else 0} }},")

    if not flags:
        return None, []
    cvar = plan.table(_join_ident(ename, fname, "c"))
    lines = list(side)
    lines.append(f"static const struct json_constraint {cvar} = {{")
    lines.append(f"{_INDENT}.flags = " + " | ".join(flags) + ",")
    lines += members
    lines += union
    lines.append("};")
    return cvar, lines


def _field_entry(
        ename: str, key: str, fname: str, desc: dict, schema_pfx: str,
        scope_name: str, pfx: str, req_bit: "int | None", required: bool,
        cvar: "str | None", plan: _IdentPlan) -> str:
    """Return the C designated initializer for one struct json_field entry."""
    kind = desc["kind"]
    is_array = _is_array_kind(kind)
    cfield = _json_member(fname) if kind == "dynamic" else fname
    # .name/.name_len are the key's raw bytes, not JSON text: the marshaller
    # feeds them to json_emit_str, which escapes and quotes them exactly as it
    # does a string value, and the same bytes are what the lookup matches an
    # incoming key against.  Escaping them here as well would emit the escapes
    # themselves as key content and put the escaped length in .name_len.
    esc, esclen = _c_string_literal(key)
    parts = [
        f'.name = "{esc}"',
        f".name_len = {esclen}",
        f".kind = {_kind_const(desc)}",
    ]
    if is_array:
        parts.append(".is_array = true")
    # .required drives marshal presence (a required array/object always emits)
    # and is schema-derived, so it stays set even under --no-validate, where
    # .req_bit -- consumed only by unmarshal's required_mask check -- is -1.
    if required:
        parts.append(".required = true")
    parts.append(f".req_bit = {req_bit if req_bit is not None else -1}")
    parts.append(f".offset = offsetof(struct {ename}, {cfield})")
    if is_array:
        parts.append(
            f".count_offset = offsetof(struct {ename}, {_count_member(fname)})")
    if kind in ("object", "array_object"):
        child_scope = _scope_of_child(
            _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
        parts.append(f".child = &{plan.schema_table[child_scope]}")
    if cvar is not None:
        parts.append(f".constraint = &{cvar}")
    return "{ " + ", ".join(parts) + " }"


def generate_tables_c(
        scopes: list, pfx: str, schema_pfx: str, do_unmarshal: bool,
        validate: bool, strict: bool, plan: _IdentPlan) -> list:
    """Emit per-scope descriptor tables (constraints, defaults image, field
    table, schema object).  Innermost scopes first so child schemas are
    defined before the parents that reference them.

    Each table is named through *plan* as it is emitted (_IdentPlan.table),
    and each scope's schema object is recorded in plan.schema_table for its
    parent's field table and for generate_wrappers_c."""
    lines = []
    scopes_map = {sn: (ks, nd) for sn, ks, nd in scopes}
    for scope_name, keys, node in reversed(scopes):
        ename = _ext(scope_name, pfx)
        fname_map = _make_field_map(keys, node)
        required = _required_set(node)
        req_keys = [k for k in keys if k in required]
        req_bit_map = {k: i for i, k in enumerate(req_keys)}
        n_required = len(req_keys)
        if validate and n_required > 64:
            sys.exit(
                f"error: scope {scope_name!r} has {n_required} required "
                "properties; at most 64 are supported")

        # Marshal presence sentinel for optional nested objects: the first
        # required string field, in field-table (sorted-key) order.
        present_field = -1
        for i, key in enumerate(keys):
            if key in required and \
                    _infer_c_type(node["properties"][key])["kind"] == "string":
                present_field = i
                break

        # Per-field constraints + enum side arrays (validation only).
        cvars: dict = {}
        if do_unmarshal and validate:
            for key in keys:
                prop = node["properties"][key]
                desc = _infer_c_type(prop)
                kind = desc["kind"]
                fname = fname_map[key]
                if kind in ("string", "int", "uint", "double", "bool"):
                    cvar, clines = _build_constraint_c(
                        ename, fname, kind, prop, None, plan)
                elif kind == "array_string":
                    cvar, clines = _build_constraint_c(
                        ename, fname, "string", prop.get("items", {}), prop, plan)
                elif kind == "array_primitive":
                    item = prop.get("items", {})
                    cvar, clines = _build_constraint_c(
                        ename, fname, _infer_c_type(item)["kind"], item, prop, plan)
                elif kind == "array_object":
                    cvar, clines = _build_constraint_c(
                        ename, fname, None, {}, prop, plan)
                else:
                    cvar, clines = None, []
                if cvar is not None:
                    cvars[key] = cvar
                    lines += clines

        # Defaults image (consumed by json_unmarshal only).
        defaults_var = None
        if do_unmarshal:
            dlines = _collect_object_defaults(
                scope_name, schema_pfx, scopes_map, _INDENT)
            if dlines:
                defaults_var = plan.table(_join_ident(ename, "defaults"))
                lines.append(
                    f"static const struct {ename} {defaults_var} = {{")
                lines += dlines
                lines.append("};")

        # Field table, in sorted-key (== lookup-index) order.
        fields_var = plan.table(_join_ident(ename, "fields"))
        lines.append(f"static const struct json_field {fields_var}[] = {{")
        for key in keys:
            desc = _infer_c_type(node["properties"][key])
            rb = req_bit_map.get(key) if validate else None
            lines.append(
                f"{_INDENT}" + _field_entry(
                    ename, key, fname_map[key], desc, schema_pfx, scope_name,
                    pfx, rb, key in required, cvars.get(key), plan) + ",")
        lines.append("};")

        # Schema object.
        req_mask = (1 << n_required) - 1 if (validate and n_required) else 0
        schema_var = plan.table(_join_ident(ename, "schema"))
        plan.schema_table[scope_name] = schema_var
        lines.append(f"static const struct json_schema {schema_var} = {{")
        lines.append(f"{_INDENT}.fields = {fields_var},")
        lines.append(f"{_INDENT}.n_fields = {len(keys)},")
        lines.append(f"{_INDENT}.obj_size = sizeof(struct {ename}),")
        if do_unmarshal:
            lines.append(
                f"{_INDENT}.lookup = {_lookup_root(pfx, scope_name)},")
        if defaults_var is not None:
            lines.append(f"{_INDENT}.defaults = &{defaults_var},")
        if req_mask:
            lines.append(
                f"{_INDENT}.required_mask = UINT64_C({hex(req_mask)}),")
        lines.append(f"{_INDENT}.present_field = {present_field},")
        if strict and do_unmarshal:
            lines.append(f"{_INDENT}.strict = true,")
        lines.append("};")
        lines.append("")
    return lines


def generate_wrappers_c(
        scopes: list, pfx: str, do_structs: bool, do_unmarshal: bool,
        do_marshal: bool, sub_schema: bool, schema_table: dict) -> list:
    """Emit the thin public free/unmarshal/marshal wrappers that forward to the
    generic table-driven runtime.  Only the root scope is public unless
    --sub-schema; nested scopes are reached through their parent's schema."""
    lines = []
    root_scope = scopes[0][0]
    for scope_name, _, _ in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        schema_var = schema_table[scope_name]
        if do_structs:
            lines += [
                f"void {make_fn_name('free', scope_name, pfx)}("
                f"struct {ename} *obj)",
                "{",
                f"{_INDENT}json_free(&{schema_var}, obj);",
                "}",
                "",
            ]
        if do_unmarshal:
            lines += [
                f"bool {make_fn_name('unmarshal', scope_name, pfx)}(",
                f"{_INDENT}struct {ename} *obj, char *json, size_t length)",
                "{",
                f"{_INDENT}return json_unmarshal("
                f"&{schema_var}, obj, json, length);",
                "}",
                "",
            ]
        if do_marshal:
            lines += [
                f"int {make_fn_name('marshal', scope_name, pfx)}(",
                f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj, "
                "const char *indent)",
                "{",
                f"{_INDENT}return json_marshal("
                f"&{schema_var}, buf, bufsz, obj, indent);",
                "}",
                "",
            ]
    return lines


# ---------------------------------------------------------------------------
# Top-level process function
# ---------------------------------------------------------------------------

def _out_stem(schema_path: Path, opts: argparse.Namespace) -> str:
    """Return the sanitized basename stem of the generated .gen.{h,c} files.

    --output-name overrides the schema stem; either is run through to_c_ident
    to keep generated file names consistent with the identifier convention.
    """
    return to_c_ident(opts.output_name) if opts.output_name \
        else to_c_ident(schema_path.stem)


def process(schema_path: Path, opts: argparse.Namespace) -> None:
    """Generate the C header/source pair for one schema file."""
    print("processing " + str(schema_path))
    with schema_path.open() as f:
        schema = json.load(f)
    _reject_malformed_keywords(schema)
    schema = _canonicalize(schema)

    stem = schema_path.stem
    schema_pfx = stem[: -len("_schema")] if stem.endswith("_schema") else stem
    # schema_pfx seeds every scope name, and thus the struct/enum tags and
    # function names derived from it, so it must be a valid C identifier.  The
    # schema filename is not constrained to be one, so run it through
    # to_c_ident(): a schema named e.g. "9cfg_schema.json" would otherwise emit
    # "struct 9cfg" (a tag starting with a digit) and other non-compiling
    # identifiers.  A stem that sanitizes to a keyword needs the same defense
    # the property names get in _make_field_map: "int_schema.json" would
    # otherwise emit "struct int".
    schema_pfx = _escape_keyword(to_c_ident(schema_pfx))
    # The user-supplied prefix seeds the same file-scope struct/enum tags,
    # lookup names, and function names as schema_pfx, so it too must be a
    # valid, non-reserved C identifier -- gen_embed.py sanitizes its --prefix
    # the same way.  Normalize it once here (e.g. "my-api" -> "my_api", a
    # leading digit or '_' gains a leading 'x'); the trailing-underscore
    # convention make_fn_name/_lookup_root document is preserved because
    # to_c_ident keeps a trailing '_'.  The empty (default) prefix is left as
    # is: to_c_ident("") would become "x" and prefix every unprefixed symbol.
    pfx = _escape_keyword(to_c_ident(opts.prefix)) if opts.prefix else ""
    scope_paths: dict = {}
    scopes = list(collect_scopes(schema, schema_pfx, paths=scope_paths))
    if not scopes:
        sys.exit(
            "error: no object scopes with fixed properties found in "
            + str(schema_path)
        )

    # Distinct JSON paths can map to the same C identifier (e.g. a property
    # named "a_b" vs. a nested path a.b); the resulting duplicate struct/
    # function definitions would not compile, so fail early.
    seen_scopes = set()
    for scope_name, _, _ in scopes:
        if scope_name in seen_scopes:
            sys.exit(
                f"error: scope name collision: two JSON object paths map to "
                f"the C identifier {scope_name!r}; rename the conflicting "
                "properties")
        seen_scopes.add(scope_name)

    do_structs = opts.do_structs
    do_unmarshal = opts.do_unmarshal
    do_marshal = opts.do_marshal
    do_lookup = opts.do_lookup

    # Enum constants are file-scope identifiers named <ENAME>_<FIELD> with both
    # parts uppercased.  _make_enum_const_map keeps them unique *within* a
    # scope, but distinct scopes have no shared view, so uppercasing can
    # collapse constants from two different scopes onto the same token even
    # when the scope names stay distinct -- e.g. sibling object properties
    # "Sub"/"sub" (whose case-preserving scope names differ but whose enum
    # prefixes both fold to <PFX>_SUB_), or a scalar "bar_x" beside a nested
    # object "bar" carrying "x" (both yield <PFX>_BAR_X).  A duplicate
    # enumerator does not compile, so reject it early the same way as a scope
    # name collision.  The check uses the very map that emits the constants, so
    # it can never diverge from what is generated.
    #
    # Guard only when an enum is actually emitted: the <ENAME>_<FIELD>
    # enumerators exist solely under do_lookup (the public key enum) or
    # fast-backend do_unmarshal (the internal one).  Structs-only, size-backend
    # unmarshal and marshal-only generation emit no enum, so a case-collision
    # between would-be
    # enumerators never materializes and must not reject an otherwise valid
    # schema.
    if do_lookup or (do_unmarshal and opts.optimize != "size"):
        enum_const_owner = {}
        for scope_name, keys, node in scopes:
            ename = _ext(scope_name, pfx)
            for const_name in _make_enum_const_map(
                    keys, node, ename).values():
                owner = enum_const_owner.get(const_name)
                if owner is not None:
                    sys.exit(
                        f"error: enum constant collision: scopes {owner!r} "
                        f"and {scope_name!r} both emit the C enumerator "
                        f"{const_name!r}; rename the conflicting properties")
                enum_const_owner[const_name] = scope_name

    # Warn about constructs that silently degrade to raw JSON fragments and
    # constraint keywords the generator does not enforce.
    _warn_unsupported_props(schema, strict=opts.strict, check_own=True)

    # Output names affect only file paths; module symbols and guards derive
    # from the schema stem and prefix.
    out_stem = _out_stem(schema_path, opts)
    # Keep the module identifier case-sensitive: distinct prefixes and names
    # must remain distinct even when their output basenames coincide.
    guard = "CSNIPPETS_SCHEMA_GEN_H_" + _ext(schema_pfx, pfx)
    h_path = schema_path.parent / (out_stem + ".gen.h")
    c_path = schema_path.parent / (out_stem + ".gen.c")

    # Claim every file-scope identifier the output defines and name the
    # suffix-derived helpers around them; exits on a clash no helper rename
    # can settle.
    plan = _plan_identifiers(scopes, scope_paths, pfx, opts, guard)

    # ===================================================================
    # Header
    # ===================================================================
    # ---- collect header includes ----------------------------------------
    h_sys_includes = set()
    h_sys_includes.add("#include <stddef.h>")
    if do_structs:
        h_sys_includes.add("#include <stdbool.h>")
        h_sys_includes.add("#include <stdint.h>")
    h_proj_includes = set()
    if do_structs:
        h_proj_includes.add('#include "' + opts.inc_pfx + 'json.h"')
    h_lines = [
        "/** @file " + h_path.name,
        " * Auto-generated by scripts/gen_schema.py from "
        + schema_path.name + " -- do not edit. */",
        "#ifndef " + guard,
        "#define " + guard,
        "",
    ] + (sorted(h_proj_includes) + [""] if h_proj_includes else []) + sorted(h_sys_includes) + [""]

    if do_lookup:
        h_lines += ["/** @name Key tables", " *  @{ */", ""]
        for scope_name, keys, node in scopes:
            ename = _ext(scope_name, pfx)
            lookup_name = _lookup_root(pfx, scope_name)
            enum_const = _make_enum_const_map(keys, node, ename)
            enum_members = [
                _INDENT
                + enum_const[key]
                + " = "
                + str(i)
                + ","
                for i, key in enumerate(keys)
            ]
            h_lines += (
                [
                    f"enum {plan.enum_tag[scope_name]} {{",
                ]
                + enum_members
                + [
                    "};",
                    f"/* Look up str (length len) in the {ename} "
                    f"{'lookup' if opts.optimize == 'size' else 'perfect-hash'}"
                    f" table; returns key index or -1. */",
                    f"int {lookup_name}(const char *str, size_t len);",
                    "",
                ]
            )
        h_lines += ["/** @} */", ""]

    if do_structs:
        h_lines += ["/** @name Struct types", " *  @{ */", ""]
        h_lines += generate_structs_h(scopes, pfx, schema_pfx)
        h_lines += ["/** @} */", ""]

    if do_unmarshal:
        h_lines += ["/** @name Unmarshal", " *  @{ */", ""]
        h_lines += generate_unmarshal_h(scopes, pfx, opts.sub_schema)
        h_lines += ["/** @} */", ""]

    if do_marshal:
        h_lines += ["/** @name Marshal", " *  @{ */", ""]
        h_lines += generate_marshal_h(scopes, pfx, opts.sub_schema)
        h_lines += ["/** @} */", ""]

    if do_structs:
        h_lines += ["/** @name Free", " *  @{ */", ""]
        h_lines += generate_free_h(scopes, pfx, opts.sub_schema)
        h_lines += ["/** @} */", ""]

    h_lines += ["#endif /* " + guard + " */", ""]

    # ===================================================================
    # C implementation
    # ===================================================================
    # ---- emit the key-lookup functions, tracking which includes they need --
    used_bsearch = False
    lookup_lines: list = []
    if do_lookup or do_unmarshal:
        lookup_lines += ["/** @name Key tables", " *  @{ */", ""]
        for scope_name, keys, _ in scopes:
            ename = _ext(scope_name, pfx)
            lookup_name = _lookup_root(pfx, scope_name)
            helper_root = plan.lookup_helper_root[scope_name]
            print("  " + ename + ": " + str(len(keys)) + " keys")
            kind = _lookup_kind(keys, opts.optimize)
            if kind == "switch":
                c_src = _try_single_byte_lookup(
                    lookup_name, keys, public_lookup=do_lookup)
            elif kind == "bsearch":
                if opts.optimize != "size":
                    print(
                        f"  note: {ename} has a key gperf cannot index (see "
                        "_gperf_safe_keys); using the bsearch lookup instead",
                        file=sys.stderr)
                used_bsearch = True
                c_src = _generate_bsearch_lookup_c(
                    lookup_name, helper_root, keys, public_lookup=do_lookup)
            else:
                c_src = _run_gperf(lookup_name, helper_root, keys)
                c_src = _postprocess_gperf(
                    c_src, lookup_name, helper_root, public_lookup=do_lookup)
            lookup_lines += ["/* --- " + ename + " --- */", c_src]
        lookup_lines += ["/** @} */", ""]

    # The --optimize mode selects the code-generation backend: 'size' emits
    # compact descriptor tables consumed by the generic runtime in json.h;
    # 'fast' emits bespoke per-scope functions (larger object code, no runtime
    # interpretation overhead).  Either backend pairs with the matching lookup
    # strategy already chosen above (bsearch for size, gperf for fast).
    use_tables = opts.optimize == "size"

    # ---- collect source includes -----------------------------------------
    c_sys_includes: set = set()
    c_proj_includes: set = set()
    if use_tables:
        # Table backend: descriptor tables + the generic runtime in json.h.
        c_sys_includes |= {
            "#include <stddef.h>",  # offsetof
            "#include <stdbool.h>",  # true/false in the tables
            "#include <stdint.h>",  # UINT64_C / INTMAX_C / UINTMAX_C
        }
        if do_lookup or do_unmarshal:
            # generated lookups use memcmp; bsearch lookups also use bsearch.
            c_sys_includes.add("#include <string.h>")
            if used_bsearch:
                c_sys_includes.add("#include <stdlib.h>")
        if do_structs:
            c_proj_includes.add('#include "' + opts.inc_pfx + 'json.h"')
    else:
        # Function backend: bespoke per-scope functions, no generic runtime.
        if do_unmarshal or do_lookup:
            c_sys_includes.add("#include <string.h>")
        if do_structs or do_unmarshal or do_lookup:
            c_sys_includes.add("#include <stdlib.h>")
        if do_marshal:
            c_sys_includes.add("#include <limits.h>")  # INT_MAX
            c_sys_includes.add("#include <stdio.h>")
            c_sys_includes.add("#include <stdint.h>")  # SIZE_MAX
            c_sys_includes.add("#include <string.h>")  # memcpy in EMIT_LIT
            if _has_double_fields(scopes):
                c_sys_includes.add("#include <math.h>")  # isfinite
        if do_unmarshal and opts.validate and _needs_is_multiple(scopes):
            c_sys_includes.add("#include <float.h>")  # DBL_EPSILON
        if do_unmarshal or do_marshal:
            c_proj_includes.add('#include "' + opts.inc_pfx + 'json.h"')

    c_lines = [
        "/** @file " + c_path.name,
        " * Auto-generated by scripts/gen_schema.py from "
        + schema_path.name + " -- do not edit. */",
        '#include "' + h_path.name + '"',
        "",
    ] + (sorted(c_proj_includes) + [""] if c_proj_includes else []) \
        + sorted(c_sys_includes) + ([""] if c_sys_includes else [])

    c_lines += lookup_lines

    if use_tables:
        if do_structs:
            c_lines += ["/** @name Schema tables", " *  @{ */", ""]
            c_lines += generate_tables_c(
                scopes, pfx, schema_pfx, do_unmarshal, opts.validate,
                opts.strict, plan)
            c_lines += ["/** @} */", ""]

            c_lines += ["/** @name Codec functions", " *  @{ */", ""]
            c_lines += generate_wrappers_c(
                scopes, pfx, do_structs, do_unmarshal, do_marshal,
                opts.sub_schema, plan.schema_table)
            c_lines += ["/** @} */", ""]
    else:
        # Function backend.  When the public enum is not exported (no 'lookup'
        # feature), the unmarshal switch still needs the key constants, so
        # define them internally here.
        if do_unmarshal and not do_lookup:
            c_lines += ["/** @name Key indices", " *  @{ */", ""]
            for scope_name, keys, node in scopes:
                ename = _ext(scope_name, pfx)
                enum_const = _make_enum_const_map(keys, node, ename)
                enum_members = [
                    _INDENT + enum_const[key]
                    + " = " + str(i) + ","
                    for i, key in enumerate(keys)
                ]
                c_lines += [f"enum {plan.enum_tag[scope_name]} {{"] + enum_members + ["};", ""]
            c_lines += ["/** @} */", ""]
        if do_structs:
            c_lines += ["/** @name Free", " *  @{ */", ""]
            c_lines += generate_free_c(
                scopes, pfx, schema_pfx, opts.sub_schema)
            c_lines += ["/** @} */", ""]
        if do_unmarshal:
            c_lines += ["/** @name Unmarshal", " *  @{ */", ""]
            if opts.validate and _needs_is_multiple(scopes):
                c_lines += _gen_is_multiple_helper()
            c_lines += generate_unmarshal_c(
                scopes, pfx, schema_pfx, opts.sub_schema, opts.validate,
                opts.strict)
            c_lines += ["/** @} */", ""]
        if do_marshal:
            c_lines += ["/** @name Marshal", " *  @{ */", ""]
            c_lines += generate_marshal_c(
                scopes, pfx, schema_pfx, plan.marshal_impl, opts.sub_schema)
            c_lines += ["/** @} */", ""]

    h_path.write_text("\n".join(h_lines))
    c_path.write_text("\n".join(c_lines))
    print("  wrote " + str(h_path))
    print("  wrote " + str(c_path))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Parse arguments and generate C code for each input schema."""
    parser = argparse.ArgumentParser(
        description="Generate C code from JSON Schema files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("schemas", metavar="schema.json", nargs="+")
    parser.add_argument(
        "--generate",
        metavar="FEATURES",
        default="structs,unmarshal,marshal",
        help=(
            "Comma-separated features to generate: "
            "structs, unmarshal, marshal, lookup "
            "(default: structs,unmarshal,marshal). "
            "Dependency rules: unmarshal/marshal each imply structs; "
            "lookup exposes the enum and lookup function publicly "
            "(lookup tables are always generated internally for unmarshal). "
            "Free functions are always generated with structs."
        ),
    )
    parser.add_argument(
        "--prefix",
        metavar="S",
        default="",
        help=(
            "Prepend S to every public generated symbol "
            "(struct types, functions, enums, lookup functions), joined "
            "with a single '_' whether or not S ends in one"
        ),
    )
    parser.add_argument(
        "--optimize",
        metavar="MODE",
        choices=["fast", "size"],
        default="fast",
        help=(
            "Selects both the code-generation backend and the key-lookup "
            "strategy. "
            "fast (default): bespoke per-scope unmarshal/marshal functions + "
            "gperf perfect-hash lookup (fastest runtime, larger object code). "
            "size: compact descriptor tables driven by the generic runtime in "
            "json.h + memcmp binary-search lookup (much smaller object code, "
            "no gperf dependency; ~6-18%% slower per (un)marshal). "
            "Keys are emitted as quoted literals so gperf handles almost "
            "arbitrary bytes; an empty key or a key containing '?' falls "
            "back to binary search."
        ),
    )
    parser.add_argument(
        "--sub-schema",
        action="store_true",
        default=False,
        help=(
            "Also generate public free/unmarshal/marshal functions for "
            "nested sub-schemas.  By default only the root object's "
            "functions are public; nested helpers are static."
        ),
    )
    parser.add_argument(
        "--include-prefix",
        metavar="P",
        default="codec",
        help=(
            "Prepend directory prefix P/ to project includes "
            '(e.g. --include-prefix codec changes #include "json.h" '
            'to #include "codec/json.h")'
        ),
    )
    parser.add_argument(
        "--output-name",
        metavar="BASE",
        default=None,
        help=(
            "Basename of the generated files (default: the schema stem), so "
            "the output is BASE.gen.{h,c}; sanitized to a valid C identifier. "
            "Generated symbols and the header guard still derive "
            "from the schema stem, so one schema can be emitted to several "
            "files in the same directory -- told apart by --prefix -- e.g. a "
            "fast and a size variant side by side."
        ),
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        default=False,
        help=(
            "Omit schema-constraint validation from the generated unmarshal "
            "functions.  By default a uint_fast64_t presence bitmask verifies "
            "that every required field appeared in the JSON input (robust "
            "against duplicate keys), and constraint keywords (minimum, "
            "maximum, minLength, enum, const, minItems, maxItems, ...) are "
            "checked; the function returns false on any violation."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help=(
            "Reject unknown keys in the generated unmarshal functions "
            "(additionalProperties: false semantics).  By default unknown "
            "keys are skipped."
        ),
    )
    parser.add_argument(
        "--indent",
        metavar="STYLE",
        default="tab",
        help=(
            "Indentation style for generated C code.  'tab' (default) "
            "uses a single \\t per level; an integer N uses N spaces "
            "per level (e.g. --indent 4)."
        ),
    )
    opts = parser.parse_args()
    opts.validate = not opts.no_validate

    global _INDENT
    ind = opts.indent.strip()
    if ind.lower() == "tab":
        _INDENT = "\t"
    else:
        _INDENT = " " * int(ind)

    # A misspelled feature must not be silently dropped: it would remove a
    # whole generation pass while still exiting 0, and the breakage would
    # surface much later as an unrelated link error against a function that
    # was never emitted.
    features = {f.strip() for f in opts.generate.split(",") if f.strip()}
    unknown = sorted(features - _FEATURES)
    if unknown:
        sys.exit(
            "error: unknown --generate feature(s): "
            + ", ".join(repr(f) for f in unknown)
            + "; known features are "
            + ", ".join(sorted(_FEATURES))
        )
    if not features:
        sys.exit(
            "error: --generate names no features; known features are "
            + ", ".join(sorted(_FEATURES))
        )
    do_lookup = "lookup" in features
    do_unmarshal = "unmarshal" in features
    do_marshal = "marshal" in features
    do_structs = "structs" in features or do_unmarshal or do_marshal
    opts.do_structs = do_structs
    opts.do_unmarshal = do_unmarshal
    opts.do_marshal = do_marshal
    opts.do_lookup = do_lookup
    opts.inc_pfx = opts.include_prefix.rstrip(
        "/") + "/" if opts.include_prefix else ""

    # Derive every output path up front and reject two distinct inputs that
    # would write the same .gen.{h,c} pair (e.g. same-directory "a-b.json" and
    # "a_b.json" both sanitize to "a_b").  Writing them in sequence would let
    # the second silently clobber the first while the run still exits 0, so a
    # build could compile code for the wrong schema.  A single input listed
    # twice targets its own files and is allowed.
    out_owner: dict = {}
    for arg in opts.schemas:
        schema_path = Path(arg)
        out_stem = _out_stem(schema_path, opts)
        for suffix in (".gen.h", ".gen.c"):
            out_path = str(schema_path.parent / (out_stem + suffix))
            prev = out_owner.get(out_path)
            if prev is not None and prev != str(schema_path):
                sys.exit(
                    f"error: {schema_path} and {prev} both generate "
                    f"{out_path}; rename one input, or generate them in "
                    "separate invocations with a distinct --output-name")
            out_owner[out_path] = str(schema_path)

    for arg in opts.schemas:
        process(Path(arg), opts)


if __name__ == "__main__":
    main()
