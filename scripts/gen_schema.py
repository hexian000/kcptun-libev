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
                           functions + gperf perfect-hash lookup.  Direct
                           dispatch; larger object code; needs gperf.
                         size: compact descriptor tables interpreted by the
                           generic runtime in json.h + memcmp binary-search
                           lookup.  Object code shrinks dramatically (the
                           per-scope logic lives once in the runtime) at the
                           cost of table interpretation; no gperf needed.
                         Keys are emitted as quoted literals, so gperf
                         handles almost arbitrary bytes; an empty key, or
                         a key containing '?' (both of which gperf cannot
                         take), falls back to binary search.
                         NOTE: both modes require the shared runtime
                         (json_unmarshal/json_marshal/json_free) in codec/json.
    --presence           Track actual input properties with named bitfields.
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
    * Fixed-property duplicates are last-value-wins; maps retain ordered
      duplicate entries. Map keys and string values carry byte lengths,
      including embedded NUL. Unconstrained map numbers retain their text.
    * Missing properties receive complete defaults/type zeros and marshal
      emits every property. Defaults do not satisfy required input checks;
      zero fallbacks need not satisfy schema constraints when re-encoded.
    * --presence instead emits has_<field> bitfields. Absent member storage
      is untouched; marshal/free access only flagged members. Caller-built
      output must initialize each value before setting its flag.
    * Input strings/fragments borrow the mutable input buffer. Generated
      json_defaults backing and array/map entries are owned per instance;
      free every successful parse, even one containing only scalar fields.
    * Map object/array values stay complete, syntax-checked raw fragments.
      Their children/deep schema are not decoded or validated; the caller
      explicitly parses them later. Fixed nested objects and object arrays
      retain generated recursive parsing.
    * additionalProperties is per object: false rejects extras, a supported
      schema checks extras, omission/true allows them. Fixed objects discard
      accepted extras.
    * Extended codec functions take optional json_options for map filters and
      one synchronous first-error callback with borrowed structured paths and
      root-relative byte offsets. Output filters must be stable across calls.
    * Marshal follows snprintf semantics and rejects non-finite doubles.
      indent selects pretty output; NULL selects compact output.
    * minLength/maxLength measure UTF-8 bytes. Supported scalar constraints
      include bounds, multipleOf, const and enum; arrays support item checks
      and minItems/maxItems. Unsupported refs, unions, boolean subschemas,
      patterns and nested-array schemas retain raw-fragment fallback; other
      unsupported validation keywords are omitted without warnings. Invalid
      keyword values and unrepresentable supported defaults remain errors.
    * Generated layouts/descriptors changed: regenerate with the matching
      runtime. Maps replace former raw object members with typed entries.

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
from decimal import Decimal
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
_PRESENCE = False


class _JsonNumber(float):
    """Retain legal number spelling for untyped defaults and raw fragments.

    Schema-directed arithmetic still uses float semantics; supported C doubles
    are range-checked separately. Instance data must not lose digits or turn
    a large exponent into an Infinity token during default serialization.
    """

    def __new__(cls, text):
        number = super().__new__(cls, text)
        number.text = text
        return number


def _default_spelling(value) -> str:
    if isinstance(value, _JsonNumber):
        return value.text
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" +
                              _default_spelling(item) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_default_spelling(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False)

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
            if isinstance(prop, dict) else None

    # Step 3: resolve duplicates.  Sort by (C identifier, JSON key) so that
    # colliding keys are grouped together and the assignment of plain name vs
    # suffix depends only on the C identifier ordering, not on JSON key
    # characters that have no C meaning (e.g. '-' vs '_').
    used: set = set() if _PRESENCE else {"json_defaults"}
    result: dict = {}
    for key in sorted(keys, key=lambda k: (raw[k], k)):
        base = raw[key]
        cand, n = base, 1
        while cand in used or _derived_member(kinds[key], cand) in used or (_PRESENCE and "has_" + cand in used):
            n += 1
            cand = _join_ident(base, str(n))
        used.add(cand)
        if _PRESENCE:
            used.add("has_" + cand)
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
    * Subschemas — recursively canonicalized; instance data stays verbatim.
    """
    if isinstance(node, list):
        return [_canonicalize(item) for item in node]
    if not isinstance(node, dict):
        return node
    result = {}
    for k, v in node.items():
        if k in ("properties", "$defs", "definitions", "dependentSchemas") \
                and isinstance(v, dict):
            result[k] = {name: _canonicalize(child)
                         for name, child in sorted(v.items())}
        elif k == "required" and isinstance(v, list):
            result[k] = sorted(set(v))
        elif k in ("items", "allOf", "anyOf", "oneOf", "not", "if", "then",
                   "else", "prefixItems", "contains", "additionalProperties",
                   "propertyNames", "unevaluatedItems", "unevaluatedProperties"):
            result[k] = _canonicalize(v)
        else:
            result[k] = v
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
    """Plan fixed objects and maps; map container values remain opaque."""
    if not isinstance(node, dict):
        return
    if node.get("type") == "object" and _infer_c_type(node)["kind"] != "dynamic":
        name = prefix if not path else _join_ident(prefix, to_c_ident(path))
        keys = sorted(node.get("properties", {}))
        if paths is not None:
            paths[name] = path
        yield name, keys, node
        for prop, child in sorted(node.get("properties", {}).items()):
            child_path = f"{path}.{prop}" if path else prop
            yield from collect_scopes(child, prefix, child_path, paths)
    elif node.get("type") == "array" and _infer_c_type(node)["kind"] == "array_object":
        yield from collect_scopes(node["items"], prefix, path, paths)


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
    if t == "null":
        return {"kind": "null"}
    if t == "object":
        if _is_dynamic_object(prop_schema):
            if "$ref" in prop_schema or "patternProperties" in prop_schema:
                return {"kind": "dynamic"}
            return {"kind": "map"}
        return {"kind": "object"}
    if t == "array":
        items = prop_schema.get("items", {})
        if not isinstance(items, dict):
            return {"kind": "dynamic"}
        item_t = items.get("type")
        if item_t == "string":
            return {"kind": "array_string"}
        if item_t == "object":
            # Unsupported object schemas have no generated child scope.
            if _infer_c_type(items)["kind"] == "dynamic":
                return {"kind": "dynamic"}
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
    'json_constraint',
    'json_context',
    'json_error',
    'json_error_kind',
    'json_field',
    'json_options',
    'json_output',
    'json_path',
    'json_schema',
    'json_string',
    'json_type',
    'json_type_kind',
    'json_val',
    'json_value',
})
_JSON_H_ORDINARY = frozenset({
    'JSON_ARRAY',
    'JSON_BOOL',
    'JSON_C_CONST',
    'JSON_C_ENUM',
    'JSON_C_EXCL_MAX',
    'JSON_C_EXCL_MIN',
    'JSON_C_MAX',
    'JSON_C_MAX_ITEMS',
    'JSON_C_MAX_LEN',
    'JSON_C_MIN',
    'JSON_C_MIN_ITEMS',
    'JSON_C_MIN_LEN',
    'JSON_C_MULT',
    'JSON_ERROR',
    'JSON_EXTRA_ALLOW',
    'JSON_EXTRA_REJECT',
    'JSON_EXTRA_TYPED',
    'JSON_E_ALLOCATION',
    'JSON_E_CONSTRAINT',
    'JSON_E_RANGE',
    'JSON_E_REQUIRED',
    'JSON_E_SYNTAX',
    'JSON_E_TYPE',
    'JSON_E_UNKNOWN',
    'JSON_K_BOOL',
    'JSON_K_DOUBLE',
    'JSON_K_DYNAMIC',
    'JSON_K_IMAX',
    'JSON_K_INT',
    'JSON_K_NULL',
    'JSON_K_OBJECT',
    'JSON_K_STRING',
    'JSON_K_UINT',
    'JSON_K_UMAX',
    'JSON_K_VALUE',
    'JSON_NEXT_END',
    'JSON_NEXT_ERROR',
    'JSON_NEXT_ITEM',
    'JSON_NULL',
    'JSON_NUMBER',
    'JSON_OBJECT',
    'JSON_PATH_INDEX',
    'JSON_PATH_MAP',
    'JSON_PATH_PROPERTY',
    'JSON_STRING',
    'json_arr_next',
    'json_codec_close',
    'json_codec_error',
    'json_codec_extra',
    'json_codec_field',
    'json_codec_init',
    'json_codec_key',
    'json_codec_open',
    'json_codec_read',
    'json_codec_release',
    'json_codec_storage',
    'json_codec_write',
    'json_codec_write_field',
    'json_format_path',
    'json_free',
    'json_iswhitespace',
    'json_iter',
    'json_marshal',
    'json_marshal_ex',
    'json_marshal_string',
    'json_obj_next',
    'json_parse',
    'json_parse_bool',
    'json_parse_double',
    'json_parse_imax',
    'json_parse_int',
    'json_parse_string',
    'json_parse_uint',
    'json_parse_umax',
    'json_unmarshal',
    'json_unmarshal_ex',
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
                for member in (fname, companion, "has_" + fname if _PRESENCE else "json_defaults"):
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
                if verb != "free":
                    plan.claim("ordinary", make_fn_name(verb + "_ex", scope_name, pfx), f"the extended {verb} function of {where}")
                plan.claim("ordinary", make_fn_name(verb, scope_name, pfx),
                           f"the {verb} function of {where}")
        if emit_lookup and keys:
            plan.claim("ordinary", _lookup_root(pfx, scope_name),
                       f"the lookup function of {where}")
        if emit_enum:
            for key, const in _make_enum_const_map(keys, node, ename).items():
                plan.claim("ordinary", const,
                           f"the enumerator for key {key!r} of {where}")

    for scope_name, keys, node in scopes:
        ename = _ext(scope_name, pfx)
        if emit_enum and keys:
            tag = plan.assign(_join_ident(ename, "key"), lambda root: {
                "tag": [root]})
            if opts.do_lookup and tag != _join_ident(ename, "key"):
                print(f"  note: the key enum of {plan.where(scope_name)} is "
                      f"named {tag!r}; the plain name is taken",
                      file=sys.stderr)
            plan.enum_tag[scope_name] = tag
        if emit_lookup and keys:
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


# ---------------------------------------------------------------------------
# Header prototypes (free / unmarshal / marshal) and schema-support warnings
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
    unmatchable member can never match, so it is dropped with no diagnostic and the
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
    if not kept:
        sys.exit(
            f"error: field {field!r}: enum has no member the {kind} field can "
            "hold; no value can satisfy it (unsatisfiable schema)")
    return sorted(set(kept))


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
    if kind in ("object", "map", "array_object"):
        return "JSON_K_OBJECT"
    if kind == "dynamic":
        return "JSON_K_DYNAMIC"
    if kind == "array_primitive":
        return {
            "int": "JSON_K_INT", "intmax_t": "JSON_K_IMAX",
            "unsigned": "JSON_K_UINT", "uintmax_t": "JSON_K_UMAX",
            "double": "JSON_K_DOUBLE", "bool": "JSON_K_BOOL",
        }[desc.get("c_base", "intmax_t")]
    if kind == "null":
        return "JSON_K_NULL"
    if kind == "value":
        return "JSON_K_VALUE"
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
        if mult_of is not None and mult_of > 0 and mult_of == math.floor(mult_of):
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
        if mult_of is not None and mult_of > 0:
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


def _map_value(node: dict) -> tuple:
    value = node.get("additionalProperties", {})
    if not isinstance(value, dict):
        value = {}
    desc = _infer_c_type(value)
    if desc["kind"] in ("object", "map") or _is_array_kind(desc["kind"]):
        desc = {"kind": "dynamic"}
    if not value or ("type" not in value and not any(
            k in value for k in ("$ref", "oneOf", "anyOf", "allOf", "patternProperties"))):
        desc = {"kind": "value"}
    return desc, value


def _value_type(desc: dict, child: str = "") -> str:
    kind = desc["kind"]
    if kind in ("string", "dynamic"):
        return "struct json_string"
    if kind == "value":
        return "struct json_value"
    if kind in ("object", "map", "array_object"):
        return "struct " + child
    if kind in ("bool", "null"):
        return "bool"
    if kind == "double":
        return "double"
    if kind == "array_string":
        return "struct json_string"
    return desc.get("c_type", desc.get("c_base", "intmax_t"))


def _fallback(node, supplied=_MISSING):
    """Expand defaults without treating missing input as validation success."""
    desc = _infer_c_type(node)
    kind = desc["kind"]
    value = supplied if supplied is not _MISSING else (
        node.get("default", _MISSING) if isinstance(node, dict) else _MISSING)
    if kind == "object":
        if value is not _MISSING and not isinstance(value, dict):
            sys.exit("error: object default must be an object")
        source = {} if value is _MISSING else value
        return {key: _fallback(prop, source.get(key, _MISSING))
                for key, prop in node["properties"].items()}
    if kind == "map":
        if value is _MISSING:
            return {}
        if not isinstance(value, dict):
            sys.exit("error: map default must be an object")
        vd, vs = _map_value(node)
        return {key: _check_default(vs, vd, item) for key, item in value.items()}
    if _is_array_kind(kind):
        if value is _MISSING:
            return []
        if not isinstance(value, list):
            sys.exit("error: array default must be an array")
        return [_fallback(node["items"], item) for item in value]
    if value is _MISSING:
        if kind == "string":
            return ""
        if kind in ("int", "uint", "double"):
            return 0
        if kind == "bool":
            return False
        if isinstance(node, dict) and node.get("type") == "object":
            return {}
        if isinstance(node, dict) and node.get("type") == "array":
            return []
        return None
    return _check_default(node, desc, value)


def _check_default(node, desc, value):
    kind = desc["kind"]
    if kind in ("int", "uint") and isinstance(value, _JsonNumber):
        exact = Decimal(value.text)
        if exact != exact.to_integral_value():
            sys.exit(f"error: default value {value.text} is not an integer")
        value = int(exact)
    if kind in ("int", "uint", "double", "string", "bool"):
        if not _const_matches_kind(value, kind):
            sys.exit(f"error: default value {value!r} has incompatible type for {kind}")
        if kind in ("int", "uint", "double"):
            _c_num_literal(value, kind, desc.get("c_type", ""))
        if kind in ("int", "uint"):
            return int(value)
    elif kind == "null" and value is not None:
        sys.exit("error: null default must be null")
    elif kind == "dynamic" and isinstance(node, dict):
        expected = node.get("type")
        if expected == "object" and not isinstance(value, dict):
            sys.exit("error: raw object default must be an object")
        if expected == "array" and not isinstance(value, list):
            sys.exit("error: raw array default must be an array")
    return value


def _codec_structs(scopes, pfx, schema_pfx, plan):
    lines = []
    for scope, keys, node in reversed(scopes):
        ename = _ext(scope, pfx)
        if not keys:
            vd, _ = _map_value(node)
            entry = plan.entries[scope]
            lines += [f"struct {entry} {{", "\tstruct json_string key;",
                      f"\t{_value_type(vd)} value;", "};",
                      f"struct {ename} {{", f"\tstruct {entry} *entries;",
                      "\tsize_t count;", "\tchar *json_defaults;", "};", ""]
            continue
        fields = _make_field_map(keys, node)
        lines.append(f"struct {ename} {{")
        if _PRESENCE:
            lines += [f"\tbool has_{fields[key]} : 1;" for key in keys]
        else:
            lines.append("\tchar *json_defaults;")
        for key in keys:
            desc = _infer_c_type(node["properties"][key])
            kind = desc["kind"]
            child = _ext(_scope_of_child(_path_from_scope(scope, schema_pfx), key, schema_pfx), pfx)
            fname = _json_member(fields[key]) if kind == "dynamic" else fields[key]
            star = "*" if _is_array_kind(kind) else ""
            lines.append(f"\t{_value_type(desc, child)} {star}{fname};")
            if star:
                lines.append(f"\tsize_t {_count_member(fields[key])};")
        lines += ["};", ""]
    return lines


def _codec_prototypes(scopes, pfx, opts):
    lines = []
    for scope, _, _ in scopes:
        if scope != scopes[0][0] and not opts.sub_schema:
            continue
        ename = _ext(scope, pfx)
        if opts.do_structs:
            lines.append(f"void {make_fn_name('free', scope, pfx)}(struct {ename} *obj);")
        if opts.do_unmarshal:
            fn = make_fn_name("unmarshal", scope, pfx)
            lines += [f"bool {fn}(struct {ename} *obj, char *json, size_t length);",
                      f"bool {make_fn_name('unmarshal_ex', scope, pfx)}(struct {ename} *obj, char *json, size_t length,",
                      "\tconst struct json_options *options);"]
        if opts.do_marshal:
            fn = make_fn_name("marshal", scope, pfx)
            lines += [f"int {fn}(char *buf, size_t bufsz, const struct {ename} *obj, const char *indent);",
                      f"int {make_fn_name('marshal_ex', scope, pfx)}(char *buf, size_t bufsz, const struct {ename} *obj,",
                      "\tconst char *indent, const struct json_options *options);"]
    return lines + [""]


def _codec_constraint(ename, fname, prop, desc, opts, plan):
    if not opts.do_unmarshal or not opts.validate:
        return None, []
    kind = desc["kind"]
    if kind == "null":
        if ("const" in prop and prop["const"] is not None) or (
                "enum" in prop and not any(item is None for item in prop["enum"])):
            sys.exit(f"error: field {fname!r}: null constraints are unsatisfiable")
        return None, []
    array = prop if _is_array_kind(kind) else None
    value = prop.get("items", {}) if array is not None else prop
    vk = _infer_c_type(value)["kind"] if isinstance(value, dict) else None
    if vk not in ("string", "int", "uint", "double", "bool"):
        vk = None
    name, lines = _build_constraint_c(ename, fname, vk, value, array, plan)
    if name is None:
        return name, lines
    # Intern the complete emitted representation, including enum contents,
    # active union and target-width expressions, rather than schema keywords.
    declarations = re.findall(r"static const [^\n=]+? (\w+)(?:\[\])? =", "\n".join(lines))
    replacements = {variable: f"VALUE_{i}" for i, variable in enumerate(declarations)}
    # Rename C identifiers, never the bytes inside a quoted string: an enum
    # value can itself spell one of these private helper names.
    normalized = re.sub(r'"(?:\\.|[^"\\])*"|[A-Za-z_]\w*',
                        lambda match: replacements.get(match[0], match[0]),
                        "\n".join(lines))
    signature = (_kind_const(desc), normalized)
    previous = plan.constraints.get(signature)
    if previous is not None and opts.optimize == "size":
        return previous, []
    plan.constraints[signature] = name
    return name, lines


def _codec_field(ename, fname, key, prop, desc, scope, pfx, schema_pfx,
                 rb, constraint, plan, entry=False):
    kind = desc["kind"]
    name, length = _c_string_literal(key)
    member = _json_member(fname) if kind == "dynamic" and not entry else fname
    parts = [f'.name = "{name}"', f".name_len = {length}",
             f".kind = {_kind_const(desc)}", f".req_bit = {rb}",
             f".offset = offsetof(struct {ename}, {member})"]
    if _is_array_kind(kind):
        parts += [".is_array = true", f".count_offset = offsetof(struct {ename}, {_count_member(fname)})"]
    if kind in ("object", "map", "array_object"):
        child = _scope_of_child(_path_from_scope(scope, schema_pfx), key, schema_pfx)
        parts.append(f".child = &{plan.schema_table[child]}")
    if constraint:
        parts.append(f".constraint = &{constraint}")
    if kind == "dynamic" and isinstance(prop, dict) and prop.get("type") in ("object", "array"):
        parts.append(".raw_type = JSON_" + prop["type"].upper())
    return "{ " + ", ".join(parts) + " }"


def _codec_tables(scopes, pfx, schema_pfx, opts, plan):
    lines = []
    for scope, keys, node in reversed(scopes):
        ename = _ext(scope, pfx)
        fmap = _make_field_map(keys, node)
        names = plan.codec[scope]
        if keys and _PRESENCE:
            get, put = names["get"], names["put"]
            lines += [f"static bool {get}(const void *value, size_t field)", "{",
                      f"\tconst struct {ename} *obj = value;", "\tswitch (field) {"]
            lines += [f"\tcase {i}: return obj->has_{fmap[key]};" for i, key in enumerate(keys)]
            lines += ["\tdefault: return false;", "\t}", "}",
                      f"static void {put}(void *value, size_t field, bool present)", "{",
                      f"\tstruct {ename} *obj = value;", "\tswitch (field) {"]
            lines += [f"\tcase {i}: obj->has_{fmap[key]} = present; break;" for i, key in enumerate(keys)]
            lines += ["\tdefault: break;", "\t}", "}"]
        req = [key for key in keys if key in _required_set(node)] if opts.validate else []
        if opts.do_unmarshal and len(req) > 64:
            sys.exit(f"error: scope {scope!r} has {len(req)} required properties; at most 64 are supported")
        entries = []
        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            cvar, clines = _codec_constraint(ename, fmap[key], prop, desc, opts, plan)
            lines += clines
            rb = req.index(key) if key in req else -1
            entries.append(_codec_field(ename, fmap[key], key, prop, desc, scope,
                                         pfx, schema_pfx, rb, cvar, plan))
        if entries:
            lines += [f"static const struct json_field {names['fields']}[] = {{"]
            lines += ["\t" + entry + "," for entry in entries] + ["};"]
        extra = node.get("additionalProperties", True)
        if not keys or isinstance(extra, dict):
            vd, vs = _map_value(node)
            cvar, clines = _codec_constraint(ename, "extra", vs, vd, opts, plan)
            lines += clines
            if keys:
                parts = [f".kind = {_kind_const(vd)}", ".req_bit = -1"]
                if cvar:
                    parts.append(f".constraint = &{cvar}")
                if vd["kind"] == "dynamic" and vs.get("type") in ("object", "array"):
                    parts.append(".raw_type = JSON_" + vs["type"].upper())
                entry = "{ " + ", ".join(parts) + " }"
            else:
                entry = _codec_field(plan.entries[scope], "value", "", vs, vd,
                                     scope, pfx, schema_pfx, -1, cvar, plan, True)
            lines.append(f"static const struct json_field {names['extra']} = {entry};")
        defaults_expr, defaults_len = None, 0
        if opts.do_unmarshal and (not _PRESENCE or not keys):
            defaults = _fallback({**node, "default": {}}) if keys else {}
            text = _default_spelling(defaults)
            escaped, defaults_len = _c_string_literal(text)
            defaults_expr = f'"{escaped}"'
            if defaults_len > 2048:
                storage = plan.table(_join_ident(ename, "default_bytes"))
                data = text.encode("utf-8") + b"\0"
                lines.append(f"static const unsigned char {storage}[] = {{")
                lines += ["\t" + ", ".join(f"0x{byte:02x}" for byte in data[i:i + 16]) + ","
                          for i in range(0, len(data), 16)]
                lines.append("};")
                defaults_expr = f"(const char *){storage}"
        lines += [f"static const struct json_schema {plan.schema_table[scope]} = {{",
                  f"\t.obj_size = sizeof(struct {ename}),"]
        if keys:
            lines += [f"\t.fields = {names['fields']},", f"\t.n_fields = {len(keys)},"]
            if opts.do_unmarshal:
                lines.append(f"\t.lookup = {_lookup_root(pfx, scope)},")
            if _PRESENCE:
                lines += [f"\t.get_present = {names['get']},", f"\t.set_present = {names['put']},"]
            if req and opts.do_unmarshal:
                lines.append(f"\t.required_mask = UINT64_C({(1 << len(req)) - 1}),")
            if opts.optimize == "fast":
                lines.append(f"\t.release = {names['release']},")
                if opts.do_unmarshal:
                    lines.append(f"\t.read = {names['read']},")
                if opts.do_marshal:
                    lines.append(f"\t.write = {names['write']},")
        else:
            lines += ["\t.is_map = true,", f"\t.entry_size = sizeof(struct {plan.entries[scope]}),",
                      f"\t.entries_offset = offsetof(struct {ename}, entries),",
                      f"\t.count_offset = offsetof(struct {ename}, count),",
                      f"\t.map_value = &{names['extra']},"]
        if extra is False:
            lines.append("\t.extra = JSON_EXTRA_REJECT,")
        elif keys and isinstance(extra, dict):
            lines += ["\t.extra = JSON_EXTRA_TYPED,", f"\t.extra_value = &{names['extra']},"]
        if not _PRESENCE or not keys:
            lines += ["\t.has_default_storage = true,",
                      f"\t.default_storage_offset = offsetof(struct {ename}, json_defaults),"]
            if opts.do_unmarshal:
                lines += [f'\t.default_json = {defaults_expr},', f"\t.default_len = {defaults_len},"]
        lines += ["};", ""]
    return lines


def _codec_fast(scopes, pfx, opts, plan, prototypes=False):
    lines = []
    for scope, keys, node in reversed(scopes):
        if not keys:
            continue
        ename = _ext(scope, pfx)
        names = plan.codec[scope]
        fmap = _make_field_map(keys, node)
        signatures = {
            "release": f"static void {names['release']}(const struct json_schema *schema, void *value)",
            "read": f"static bool {names['read']}(const struct json_schema *schema, void *value, char *json, size_t length, struct json_context *context, const struct json_path *path, bool fallback)",
            "write": f"static void {names['write']}(const struct json_schema *schema, const void *value, struct json_output *output, const struct json_path *path, int depth)",
        }
        active = ["release"] + (["read"] if opts.do_unmarshal else []) + (["write"] if opts.do_marshal else [])
        if prototypes:
            lines += [signatures[k] + ";" for k in active]
            continue
        lines += [signatures["release"], "{", f"\tstruct {ename} *obj = value;"]
        for i, key in enumerate(keys):
            gate = f"obj->has_{fmap[key]}" if _PRESENCE else "true"
            lines += [f"\tif ({gate}) {{", f"\t\tjson_codec_release(&schema->fields[{i}], obj);"]
            if _PRESENCE:
                lines.append(f"\t\tobj->has_{fmap[key]} = false;")
            lines.append("\t}")
        lines += ["\tjson_codec_storage(schema, obj);", "}", ""]
        if opts.do_unmarshal:
            lines += [signatures["read"], "{", f"\tstruct {ename} *obj = value;"]
            if _PRESENCE:
                lines += [f"\tobj->has_{fmap[key]} = false;" for key in keys]
                lines.append("\t(void)fallback;")
            else:
                lines.append("\tif (!json_codec_init(schema, obj, context, path, fallback)) { return false; }")
            lines += ["\tsize_t consumed = length;", "\tstruct json_val root = json_parse(json, &consumed);",
                      "\tif (root.type != JSON_OBJECT) {",
                      "\t\tjson_codec_error(context, path, root.type == JSON_ERROR ? JSON_E_SYNTAX : JSON_E_TYPE, NULL, root.type == JSON_ERROR ? json + consumed : json);",
                      "\t\tgoto fail;", "\t}", "\tjson_iter iter = root.iter;",
                      "\tchar *key, *raw;", "\tsize_t key_len, raw_len;", "\tuint_least64_t required = 0;", "\tint next;",
                      "\twhile ((next = json_obj_next(json, &length, &iter, &key, &key_len, &raw, &raw_len)) == JSON_NEXT_ITEM) {",
                      "\t\tstruct json_path field_path = {.parent = path, .kind = JSON_PATH_PROPERTY, .key = {key_len, key}};",
                      f"\t\tswitch ({_lookup_root(pfx, scope)}(key, key_len)) {{"]
            for i, key in enumerate(keys):
                lines += [f"\t\tcase {i}:"]
                if _PRESENCE:
                    lines += [f"\t\t\tif (obj->has_{fmap[key]}) {{ json_codec_release(&schema->fields[{i}], obj); }}",
                              f"\t\t\tobj->has_{fmap[key]} = false;"]
                else:
                    lines.append(f"\t\t\tjson_codec_release(&schema->fields[{i}], obj);")
                lines.append(f"\t\t\tif (!json_codec_field(&schema->fields[{i}], obj, raw, raw_len, context, &field_path)) {{ goto fail; }}")
                if _PRESENCE:
                    lines.append(f"\t\t\tobj->has_{fmap[key]} = true;")
                if opts.validate and key in _required_set(node):
                    rb = [k for k in keys if k in _required_set(node)].index(key)
                    lines.append(f"\t\t\trequired |= UINT64_C(1) << {rb};")
                lines.append("\t\t\tbreak;")
            lines += ["\t\tdefault:", "\t\t\tif (!json_codec_extra(schema, raw, raw_len, context, &field_path)) { goto fail; }",
                      "\t\t\tbreak;", "\t\t}", "\t}", "\tif (next != JSON_NEXT_END) {",
                      "\t\tjson_codec_error(context, path, JSON_E_SYNTAX, NULL, json + iter);", "\t\tgoto fail;", "\t}",
                      "\tif (!context->fallback && required != schema->required_mask) {"]
            for i, key in enumerate(keys):
                if opts.validate and key in _required_set(node):
                    rb = [k for k in keys if k in _required_set(node)].index(key)
                    lines += [f"\t\tif (!(required & (UINT64_C(1) << {rb}))) {{",
                              f"\t\t\tstruct json_path missing = {{.parent = path, .kind = JSON_PATH_PROPERTY, .key = {{schema->fields[{i}].name_len, (char *)schema->fields[{i}].name}}}};",
                              "\t\t\tjson_codec_error(context, &missing, JSON_E_REQUIRED, NULL, NULL);", "\t\t\tgoto fail;", "\t\t}"]
            lines += ["\t}", "\tfor (; iter < length; iter++) {",
                      "\t\tif (!json_iswhitespace((unsigned char)json[iter])) {",
                      "\t\t\tjson_codec_error(context, path, JSON_E_SYNTAX, NULL, json + iter);", "\t\t\tgoto fail;", "\t\t}", "\t}",
                      "\treturn true;", "fail:", f"\t{names['release']}(schema, obj);"]
            if not _PRESENCE:
                lines.append("\tmemset(obj, 0, sizeof(*obj));")
            lines += ["\treturn false;", "}", ""]
        if opts.do_marshal:
            lines += [signatures["write"], "{", f"\tconst struct {ename} *obj = value;",
                      "\tbool first = true;", "\tjson_codec_open(output, '{');"]
            for i, key in enumerate(keys):
                gate = f"obj->has_{fmap[key]}" if _PRESENCE else "true"
                lines += [f"\tif ({gate}) {{",
                          f"\t\tconst struct json_field *field = &schema->fields[{i}];",
                          "\t\tstruct json_path field_path = {.parent = path, .kind = JSON_PATH_PROPERTY, .key = {field->name_len, (char *)field->name}};",
                          "\t\tjson_codec_key(output, field->name, field->name_len, depth + 1, &first);",
                          "\t\tjson_codec_write_field(field, obj, output, &field_path, depth + 1);", "\t}"]
            lines += ["\tjson_codec_close(output, '}', depth, first);", "}", ""]
    return lines


def _codec_wrappers(scopes, pfx, opts, plan):
    lines = []
    for scope, _, _ in scopes:
        if scope != scopes[0][0] and not opts.sub_schema:
            continue
        ename, table = _ext(scope, pfx), plan.schema_table[scope]
        fn = make_fn_name("free", scope, pfx)
        lines += [f"void {fn}(struct {ename} *obj)", "{", f"\tjson_free(&{table}, obj);", "}", ""]
        if opts.do_unmarshal:
            fn = make_fn_name("unmarshal", scope, pfx)
            lines += [f"bool {make_fn_name('unmarshal_ex', scope, pfx)}(struct {ename} *obj, char *json, size_t length, const struct json_options *options)",
                      "{", f"\treturn json_unmarshal_ex(&{table}, obj, json, length, options);", "}",
                      f"bool {fn}(struct {ename} *obj, char *json, size_t length)", "{",
                      f"\treturn {make_fn_name('unmarshal_ex', scope, pfx)}(obj, json, length, NULL);", "}", ""]
        if opts.do_marshal:
            fn = make_fn_name("marshal", scope, pfx)
            lines += [f"int {make_fn_name('marshal_ex', scope, pfx)}(char *buf, size_t bufsz, const struct {ename} *obj, const char *indent, const struct json_options *options)",
                      "{", f"\treturn json_marshal_ex(&{table}, buf, bufsz, obj, indent, options);", "}",
                      f"int {fn}(char *buf, size_t bufsz, const struct {ename} *obj, const char *indent)", "{",
                      f"\treturn {make_fn_name('marshal_ex', scope, pfx)}(buf, bufsz, obj, indent, NULL);", "}", ""]
    return lines


def process(schema_path: Path, opts: argparse.Namespace) -> None:
    print("processing " + str(schema_path))
    with schema_path.open() as stream:
        schema = json.load(stream, parse_float=_JsonNumber)
    _reject_malformed_keywords(schema)
    schema = _canonicalize(schema)
    stem = schema_path.stem
    schema_pfx = _escape_keyword(to_c_ident(stem[:-7] if stem.endswith("_schema") else stem))
    pfx = _escape_keyword(to_c_ident(opts.prefix)) if opts.prefix else ""
    paths = {}
    scopes = list(collect_scopes(schema, schema_pfx, paths=paths))
    if not scopes:
        sys.exit("error: no supported object scopes found in " + str(schema_path))
    if len({scope for scope, _, _ in scopes}) != len(scopes):
        sys.exit("error: scope name collision; rename conflicting properties")
    guard = "CSNIPPETS_SCHEMA_GEN_H_" + _ext(schema_pfx, pfx)
    plan = _plan_identifiers(scopes, paths, pfx, opts, guard)
    plan.constraints, plan.entries, plan.codec = {}, {}, {}
    for scope, keys, _ in scopes:
        ename = _ext(scope, pfx)
        plan.schema_table[scope] = plan.table(_join_ident(ename, "schema"))
        if not keys:
            plan.entries[scope] = plan.assign(_join_ident(ename, "entry"), lambda root: {"tag": [root]})
        plan.codec[scope] = {suffix: plan.table(_join_ident(ename, suffix)) for suffix in (
            "fields", "extra", "get", "put", "read", "release", "write")}
    out = schema_path.parent / _out_stem(schema_path, opts)
    h_path, c_path = Path(str(out) + ".gen.h"), Path(str(out) + ".gen.c")
    banner = ["/** Auto-generated by scripts/gen_schema.py from " + schema_path.name + "; do not edit. */"]
    header = banner + ["#ifndef " + guard, "#define " + guard, "", "#include <stddef.h>"]
    if opts.do_structs:
        header += ['#include "' + opts.inc_pfx + 'json.h"', ""]
    lookups = []
    shared = {}
    if opts.do_lookup or opts.do_unmarshal:
        for scope, keys, node in scopes:
            if not keys:
                continue
            fn = _lookup_root(pfx, scope)
            if opts.do_lookup:
                consts = _make_enum_const_map(keys, node, _ext(scope, pfx))
                header += [f"enum {plan.enum_tag[scope]} {{"]
                header += [f"\t{consts[key]} = {i}," for i, key in enumerate(keys)]
                header += ["};", f"int {fn}(const char *str, size_t len);", ""]
            if opts.optimize == "size" and tuple(keys) in shared:
                storage = "" if opts.do_lookup else "static "
                lookups += [f"{storage}int {fn}(const char *str, size_t len)", "{",
                            f"\treturn {shared[tuple(keys)]}(str, len);", "}"]
                continue
            shared[tuple(keys)] = fn
            kind = _lookup_kind(keys, opts.optimize)
            helper = plan.lookup_helper_root[scope]
            if kind == "switch":
                source = _try_single_byte_lookup(fn, keys, opts.do_lookup)
            elif kind == "bsearch":
                source = _generate_bsearch_lookup_c(fn, helper, keys, opts.do_lookup)
            else:
                source = _postprocess_gperf(_run_gperf(fn, helper, keys), fn, helper, opts.do_lookup)
            lookups.append(source)
    if opts.do_structs:
        header += _codec_structs(scopes, pfx, schema_pfx, plan)
        header += _codec_prototypes(scopes, pfx, opts)
    header += ["#endif /* " + guard + " */", ""]
    source = banner + ['#include "' + h_path.name + '"', "", "#include <stdlib.h>", "#include <string.h>", ""] + lookups
    if opts.do_structs:
        if opts.optimize == "fast":
            source += _codec_fast(scopes, pfx, opts, plan, True)
        source += _codec_tables(scopes, pfx, schema_pfx, opts, plan)
        if opts.optimize == "fast":
            source += _codec_fast(scopes, pfx, opts, plan)
        source += _codec_wrappers(scopes, pfx, opts, plan)
    # The emitter uses tabs internally; honor the requested layout at the edge.
    h_path.write_text("\n".join(header).replace("\t", _INDENT))
    c_path.write_text("\n".join(source).replace("\t", _INDENT))
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
            "gperf perfect-hash lookup (direct object dispatch, larger object code). "
            "size: compact descriptor tables driven by the generic runtime in "
            "json.h + memcmp binary-search lookup (much smaller object code, "
            "no gperf dependency). "
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
    parser.add_argument("--presence", action="store_true",
                        help="Emit named property presence bitfields; omit absent members")
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

    global _INDENT, _PRESENCE
    _PRESENCE = opts.presence
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
        try:
            process(Path(arg), opts)
        except (ValueError, OverflowError) as error:
            sys.exit(f"error: {arg}: {error}")


if __name__ == "__main__":
    main()
