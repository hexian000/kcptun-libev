#!/usr/bin/env python3
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
                           unmarshal/marshal/lookup each imply structs.
                           lookup tables are always generated internally for
                           unmarshal; lookup only controls whether the enum
                           and lookup function are made public.
                         Free functions are always generated with structs.
    --prefix S           Prepend S to every public generated symbol:
                         struct types, function names, enum names,
                         lookup functions, and enum-value prefixes.
    --optimize MODE      fast (default): gperf perfect-hash for O(1) lookup.
                         size: sorted table + memcmp binary search;
                         smaller binary, no gperf dependency.
                         Keys are emitted as quoted literals, so gperf
                         handles arbitrary bytes; an empty key (the one
                         keyword gperf rejects) falls back to binary search.
    --strict             Reject unknown keys in unmarshal
                         (additionalProperties: false semantics).
    --no-validate        Omit schema-constraint validation from unmarshal.

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

Output per input schema:
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
# Integer range constants used by _infer_c_type
# ---------------------------------------------------------------------------

_INT32_MIN = -(2**31)
_INT32_MAX = 2**31 - 1
_UINT32_MAX = 2**32 - 1
_INT64_MIN = -(2**63)
_UINT64_MAX = 2**64 - 1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def to_c_ident(s: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", s)
    if not ident:
        # The empty string is a legal JSON key but not a legal C identifier;
        # map it to "_".  _make_field_map still resolves any collision this
        # creates (e.g. with a key like ",") by appending a numeric suffix.
        return "_"
    if ident[0].isdigit():
        ident = "_" + ident
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
    "int8_t",   "int16_t",   "int32_t",   "int64_t",
    "uint8_t",  "uint16_t",  "uint32_t",  "uint64_t",
    # Minimum-width (required)
    "int_least8_t",  "int_least16_t",  "int_least32_t",  "int_least64_t",
    "uint_least8_t", "uint_least16_t", "uint_least32_t", "uint_least64_t",
    # Fastest minimum-width (required)
    "int_fast8_t",  "int_fast16_t",  "int_fast32_t",  "int_fast64_t",
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

# Combined set used by _make_field_map to detect name collisions.
_C_KEYWORDS = (
    _C11_KEYWORDS | _STDBOOL_NAMES | _STDDEF_NAMES |
    _STDINT_NAMES | _STDIO_NAMES | _STDLIB_NAMES | _POSIX_NAMES
)


def _make_field_map(keys: list, node: dict) -> dict:
    """Return a collision-free mapping from JSON property name → C field name.

    Handles three cases in order:
    1. Non-identifier characters replaced with '_'; leading digits prefixed
       with '_' (both via to_c_ident).
    2. C reserved-word conflicts: append '_' suffix (e.g. 'int' → 'int_').
    3. Duplicate names after steps 1-2: append '_2', '_3', ... sorted by
       (C identifier, JSON key) so the result is deterministic: all colliding
       keys are grouped together and the alphabetically-first JSON key within
       each collision group keeps the plain name.
    """
    # Steps 1-2: raw conversion for every key.
    raw = {}
    for key in keys:
        ident = to_c_ident(key)
        if ident in _C_KEYWORDS:
            ident += "_"
        raw[key] = ident

    # Step 3: resolve duplicates.  Sort by (C identifier, JSON key) so that
    # colliding keys are grouped together and the assignment of plain name vs
    # suffix depends only on the C identifier ordering, not on JSON key
    # characters that have no C meaning (e.g. '-' vs '_').
    used: set = set()
    result: dict = {}
    for key in sorted(keys, key=lambda k: (raw[k], k)):
        cand = raw[key]
        if cand not in used:
            used.add(cand)
            result[key] = cand
        else:
            n = 2
            while f"{cand}_{n}" in used:
                n += 1
            new = f"{cand}_{n}"
            used.add(new)
            result[key] = new

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


def collect_scopes(node, prefix: str, path: str = ""):
    """Yield (scope_name, keys, node) for every JSON object scope with fixed
    properties.  Objects that carry only ``additionalProperties`` (dynamic
    keys, no ``properties``) are skipped — they appear as JSON-fragment
    ``char *`` / ``size_t`` fields in their parent struct instead.
    """
    if not isinstance(node, dict):
        return
    if node.get("type") == "object" and "properties" in node:
        name = prefix if not path else (prefix + "_" + to_c_ident(path))
        keys = sorted(node["properties"])
        if keys:
            yield name, keys, node
        for prop, child in sorted(node["properties"].items()):
            child_path = f"{path}.{prop}" if path else prop
            yield from collect_scopes(child, prefix, child_path)
    elif node.get("type") == "array":
        items = node.get("items", {})
        if isinstance(items, dict):
            yield from collect_scopes(items, prefix, path)
    for defs in (node.get("$defs", {}), node.get("definitions", {})):
        for _, child in sorted(defs.items()):
            yield from collect_scopes(child, prefix, path)


def _required_set(node: dict) -> set:
    """Return the set of required property names from a JSON Schema object node."""
    return set(node.get("required", []))


def _is_dynamic_object(prop_schema: dict) -> bool:
    """True when the schema node is an object with only additionalProperties
    (no fixed ``properties`` key), meaning keys are dynamic at runtime."""
    return (
        isinstance(prop_schema, dict)
        and prop_schema.get("type") == "object"
        and "properties" not in prop_schema
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
    """
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
        # Bounds exceed 64-bit range → store as a raw JSON fragment.
        if (minimum is not None and minimum < _INT64_MIN) or \
                (maximum is not None and maximum > _UINT64_MAX):
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
        item_t = items.get("type")
        if item_t == "string":
            return {"kind": "array_string"}
        if item_t == "object" and "properties" in items:
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
    visible at a glance.

    The prefix is normalised so a user-supplied trailing underscore
    (``ex_``) does not produce a double underscore in the output.
    """
    pfx = pfx.rstrip("_")
    return f"{pfx}_lookup_{scope_name}"


def _make_gperf_input(lookup_name: str, keys: list) -> str:
    """Build the complete gperf input for a scope's keys.

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
    escapes -- gperf's quoted-keyword syntax -- so any byte is representable:
    delimiters, quotes, '%'/'#', control characters, non-ASCII, and (because
    of %compare-lengths) NUL.  gperf rejects only the empty keyword, which
    _gperf_safe_keys screens out before we get here.
    """
    header_lines = [
        "%language=ANSI-C",
        "%struct-type",
        "%readonly-tables",
        "%compare-lengths",
        "%enum",
        "%pic",
        "%null-strings",
        f"%define string-pool-name {lookup_name}_stringpool",
        "%define initializer-suffix ,0",
        f"%define hash-function-name {lookup_name}_hash",
        f"%define lookup-function-name {lookup_name}_kv_lookup_",
        "%define slot-name name",
        "%{",
        f"/* {lookup_name}: {len(keys)} keys  (auto-generated -- do not edit) */",
        "%}",
        "struct " + lookup_name + "_kv { int name; int idx; };",
        "%%",
    ]
    keyword_lines = [
        f'"{_c_string_literal(key)[0]}", {i}' for i, key in enumerate(keys)
    ]
    return "\n".join(header_lines) + "\n" + "\n".join(keyword_lines) + "\n%%\n"


def _gperf_safe_keys(keys: list) -> bool:
    """True when gperf can build a lookup table for these keys.

    Keys are emitted as quoted C-string literals (see _make_gperf_input), so
    every byte is representable -- delimiters, quotes, control characters,
    non-ASCII, and (under %compare-lengths) NUL.  The only keyword gperf
    refuses is the empty string ("Empty input keyword is not allowed"), so an
    empty key is the sole case that must fall back to the bsearch lookup.
    """
    return all(len(key) > 0 for key in keys)


def _run_gperf(lookup_name: str, keys: list) -> str:
    # All options are embedded as %-declarations in the input (see
    # _make_gperf_input), so gperf is invoked with no argv options and the
    # input is fed on stdin.
    src = _make_gperf_input(lookup_name, keys)
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


def _postprocess_gperf(
        src: str, lookup_name: str, public_lookup: bool = True) -> str:
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

    # Strip the ASCII charset guard block emitted by gperf.
    # The project targets POSIX (ASCII guaranteed) so the check is
    # redundant; always stripping it also avoids duplicate blocks when
    # multiple scopes are processed per file.
    # The block starts with '#if !(('' and ends at its matching #endif
    # (depth tracking handles future gperf versions that might nest an
    # #if inside, though current gperf does not).
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
    kv_ret = "const struct " + lookup_name + "_kv *\n"
    result = ["static " + ln if ln == kv_ret else ln for ln in result]

    # Suppress -Wunused-parameter on the hash function's `str` argument.
    patched = []
    hash_sig = lookup_name + "_hash"
    in_hash_func = False
    for line in result:
        patched.append(line)
        if not in_hash_func and line.rstrip().endswith(
                hash_sig + " (register const char *str, register size_t len)"):
            in_hash_func = True
        elif in_hash_func and line.strip() == "{":
            patched.append(f"{_INDENT}(void)(str);\n")
            in_hash_func = False
    result = patched

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
        _INDENT + "const struct " + lookup_name + "_kv *kv_ = "
        + lookup_name + "_kv_lookup_(str, len);\n",
        _INDENT + "return kv_ ? kv_->idx : -1;\n",
        "}\n",
    ]
    return "".join(result)


def _generate_bsearch_lookup_c(
        lookup_name: str, keys: list, public_lookup: bool) -> str:
    """Generate a bsearch(3)-based lookup (--optimize size).

    Keys are sorted by (length, name) so the comparator can prune with a
    cheap integer comparison before calling memcmp.
    Requires <stdlib.h> (bsearch) and <string.h> (memcmp).
    """
    tbl = f"{lookup_name}_keys_"
    entry_t = f"{lookup_name}_entry_"
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
        f"}};",
        f"static int {lookup_name}_cmp_(const void *key_, const void *entry_)",
        f"{{",
        f"{_INDENT}const {entry_t} *k_ = (const {entry_t} *)key_;",
        f"{_INDENT}const {entry_t} *e_ = (const {entry_t} *)entry_;",
        f"{_INDENT}if (k_->len < e_->len) {{ return -1; }}",
        f"{_INDENT}if (k_->len > e_->len) {{ return  1; }}",
        f"{_INDENT}return memcmp(k_->name, e_->name, k_->len);",
        f"}}",
        f"{storage}int",
        f"{lookup_name}(const char *str, size_t len)",
        f"{{",
        f"{_INDENT}const {entry_t} key_ = {{str, len, 0}};",
        f"{_INDENT}const {entry_t} *e_ =",
        f"{_INDENT * 2}bsearch(&key_, {tbl}, {n}, sizeof(*{tbl}), {lookup_name}_cmp_);",
        f"{_INDENT}return e_ ? e_->idx : -1;",
        f"}}",
        "",
    ]
    return "\n".join(result)


# Sentinel for "no default present" — distinguishes missing from default=0/false/""
_MISSING = object()

# One indentation level for generated C source (default tab).
_INDENT = "\t"


def _c_string_literal(s: str) -> tuple:
    """Return (escaped C string literal content, byte length) for a default string."""
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
        elif 0x20 <= byte <= 0x7E:
            parts.append(chr(byte))
        else:
            # Three-digit octal: unlike \xNN, an octal escape consumes at
            # most three digits, so a following literal hex digit cannot be
            # absorbed into the escape sequence.
            parts.append(f"\\{byte:03o}")
    return "".join(parts), len(encoded)


def _json_escape(s: str) -> str:
    """Return s escaped for JSON string content (without surrounding quotes)."""
    return json.dumps(s)[1:-1]


def _default_designated_init(
        fname: str, kind: str, desc: dict, default_val,
        indent: "str | None" = None) -> "str | None":
    """Return a C designated-initializer string for a struct field default, or None."""
    if indent is None:
        indent = _INDENT * 2
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
        c_val = f"{default_val}.0" if isinstance(
            default_val, int) else repr(float(default_val))
        return f"{indent}.{fname} = {c_val},"
    if kind == "string" and isinstance(default_val, str):
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
        else:
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
    the identifier carries only a module+scope prefix (no verb).
    """
    return pfx + scope_name


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
    wide.
    """
    pfx = pfx.rstrip("_")
    parts = [pfx, verb, scope_name]
    if suffix:
        parts.append(suffix)
    return "_".join(p for p in parts if p)


def _scope_of_child(parent_path: str, prop_key: str, schema_pfx: str) -> str:
    """Derive the scope name for a nested property (mirrors collect_scopes logic)."""
    child_path = f"{parent_path}.{prop_key}" if parent_path else prop_key
    return schema_pfx + "_" + to_c_ident(child_path)


def _path_from_scope(scope_name: str, schema_pfx: str) -> str:
    """Reverse-engineer the JSON path string from a scope name.

    scope_name = schema_pfx                     → ""
    scope_name = schema_pfx + "_" + path_ident → path_ident (dots encoded as _)
    """
    if scope_name == schema_pfx:
        return ""
    assert scope_name.startswith(schema_pfx + "_")
    return scope_name[len(schema_pfx) + 1:]


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
                    lines.append(f"{_INDENT}struct json_string {fname}_json;")
                elif kind == "array_string":
                    lines.append(f"{_INDENT}struct json_string *{fname};")
                    lines.append(f"{_INDENT}size_t {fname}_count;")
                elif kind == "array_object":
                    child_scope = _scope_of_child(
                        _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                    child_ename = _ext(child_scope, pfx)
                    lines.append(f"{_INDENT}/* {child_ename} array */")
                    lines.append(f"{_INDENT}struct {child_ename} *{fname};")
                    lines.append(f"{_INDENT}size_t {fname}_count;")
                elif kind == "array_primitive":
                    c_base = desc.get("c_base", "int")
                    lines.append(f"{_INDENT}/* {c_base} array */")
                    lines.append(f"{_INDENT}{c_base} *{fname};")
                    lines.append(f"{_INDENT}size_t {fname}_count;")

        lines.append("};")
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Free function generation
# ---------------------------------------------------------------------------

def generate_free_h(scopes: list, pfx: str, sub_schema: bool = False) -> list:
    lines = []
    root_scope = scopes[0][0]
    for scope_name, _, _ in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        lines += [
            f"/** @brief Free heap-allocated fields inside *obj (arrays). */",
            f"void {make_fn_name('free', scope_name, pfx)}(struct {ename} *obj);",
            "",
        ]
    return lines


def generate_free_c(scopes: list, pfx: str, schema_pfx: str, sub_schema: bool = False) -> list:
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
                child_ename = _ext(child_scope, pfx)
                lines.append(f"{_INDENT}if (obj->{fname} != NULL) {{")
                lines.append(
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{")
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
# Unmarshal function generation
# ---------------------------------------------------------------------------

def _c_num_literal(val: "int | float", kind: str, c_type: str) -> str:
    """Format a numeric schema constraint value as a C literal matching c_type."""
    if kind in ("int", "uint"):
        n = int(val)
        if c_type == "intmax_t":
            return f"INTMAX_C({n})"
        if c_type == "uintmax_t":
            return f"UINTMAX_C({n})"
        if c_type == "unsigned":
            return f"{n}u"
        return str(n)
    # double
    if isinstance(val, int):
        return f"{val}.0"
    return repr(float(val))


def _scalar_constraint_checks(
        prop_schema: dict,
        kind: str,
        desc: dict,
        val_expr: str,
        indent: str,
        fail_stmt: str = "return false;",
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
    double  : same as int/uint (uses floating-point comparisons; ``multipleOf`` via fmod)
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
        const_v = prop_schema.get("const")
        enum_vs = prop_schema.get("enum")

        if min_len is not None:
            lines.append(
                f"{indent}if ({len_expr} < {min_len}u) {{ {fail_stmt} }}")
        if max_len is not None:
            lines.append(
                f"{indent}if ({len_expr} > {max_len}u) {{ {fail_stmt} }}")

        def _str_eq(v: str) -> str:
            esc, blen = _c_string_literal(str(v))
            return (f"({len_expr} == {blen}u && "
                    f"memcmp({str_expr}, \"{esc}\", {blen}) == 0)")

        if const_v is not None:
            lines.append(f"{indent}if (!{_str_eq(const_v)}) {{ {fail_stmt} }}")
        if enum_vs is not None and len(enum_vs) > 0:
            conds = " || ".join(_str_eq(str(v)) for v in enum_vs)
            lines.append(f"{indent}if (!({conds})) {{ {fail_stmt} }}")

    elif kind in ("int", "uint"):
        is_unsigned = c_type in ("unsigned", "uintmax_t")
        minimum = prop_schema.get("minimum")
        maximum = prop_schema.get("maximum")
        excl_min = prop_schema.get("exclusiveMinimum")
        excl_max = prop_schema.get("exclusiveMaximum")
        mult_of = prop_schema.get("multipleOf")
        const_v = prop_schema.get("const")
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

        # Skip minimum <= 0 for unsigned types — the parser already rejects negatives.
        if minimum is not None and not (is_unsigned and minimum <= 0):
            lines.append(
                f"{indent}if ({val_expr} < {_c_num_literal(minimum, kind, c_type)}) {{ {fail_stmt} }}")
        if maximum is not None:
            lines.append(
                f"{indent}if ({val_expr} > {_c_num_literal(maximum, kind, c_type)}) {{ {fail_stmt} }}")
        if excl_min is not None and not (is_unsigned and excl_min < 0):
            lines.append(
                f"{indent}if ({val_expr} <= {_c_num_literal(excl_min, kind, c_type)}) {{ {fail_stmt} }}")
        if excl_max is not None:
            lines.append(
                f"{indent}if ({val_expr} >= {_c_num_literal(excl_max, kind, c_type)}) {{ {fail_stmt} }}")
        if mult_of is not None:
            if mult_of <= 0 or mult_of != math.floor(mult_of):
                print(
                    f"  warning: non-integral or non-positive multipleOf "
                    f"{mult_of!r} on an integer field is not supported; "
                    f"the check is omitted", file=sys.stderr)
            else:
                lines.append(
                    f"{indent}if ({val_expr} % {_c_num_literal(mult_of, kind, c_type)} != 0) {{ {fail_stmt} }}")
        if const_v is not None:
            lines.append(
                f"{indent}if ({val_expr} != {_c_num_literal(const_v, kind, c_type)}) {{ {fail_stmt} }}")
        if enum_vs is not None and len(enum_vs) > 0:
            conds = " && ".join(
                f"{val_expr} != {_c_num_literal(v, kind, c_type)}" for v in enum_vs)
            lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    elif kind == "double":
        minimum = prop_schema.get("minimum")
        maximum = prop_schema.get("maximum")
        excl_min = prop_schema.get("exclusiveMinimum")
        excl_max = prop_schema.get("exclusiveMaximum")
        mult_of = prop_schema.get("multipleOf")
        const_v = prop_schema.get("const")
        enum_vs = prop_schema.get("enum")

        if minimum is not None:
            lines.append(
                f"{indent}if ({val_expr} < {_c_num_literal(minimum, 'double', '')}) {{ {fail_stmt} }}")
        if maximum is not None:
            lines.append(
                f"{indent}if ({val_expr} > {_c_num_literal(maximum, 'double', '')}) {{ {fail_stmt} }}")
        if excl_min is not None:
            lines.append(
                f"{indent}if ({val_expr} <= {_c_num_literal(excl_min, 'double', '')}) {{ {fail_stmt} }}")
        if excl_max is not None:
            lines.append(
                f"{indent}if ({val_expr} >= {_c_num_literal(excl_max, 'double', '')}) {{ {fail_stmt} }}")
        if mult_of is not None:
            lines.append(
                f"{indent}if (fmod({val_expr}, {_c_num_literal(mult_of, 'double', '')}) != 0.0) {{ {fail_stmt} }}")
        if const_v is not None:
            lines.append(
                f"{indent}if ({val_expr} != {_c_num_literal(const_v, 'double', '')}) {{ {fail_stmt} }}")
        if enum_vs is not None and len(enum_vs) > 0:
            conds = " && ".join(
                f"{val_expr} != {_c_num_literal(v, 'double', '')}" for v in enum_vs)
            lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    elif kind == "bool":
        const_v = prop_schema.get("const")
        enum_vs = prop_schema.get("enum")

        if const_v is not None:
            lines.append(
                f"{indent}if ({val_expr} != {'true' if const_v else 'false'}) {{ {fail_stmt} }}")
        if enum_vs is not None and len(enum_vs) > 0:
            valid = [
                "true" if v else "false" for v in enum_vs if isinstance(v, bool)]
            if valid:
                conds = " && ".join(f"{val_expr} != {v}" for v in valid)
                lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    return lines


def _schema_constraint_flags(scopes: list) -> dict:
    """Scan all property schemas for constraint keywords that require extra C includes.

    Returns a dict with boolean flags:
    - ``needs_math``: any ``multipleOf`` on a ``number`` type (requires fmod).
    """
    flags = {"needs_math": False}
    for _, keys, node in scopes:
        for key in keys:
            prop = node["properties"][key]
            if "multipleOf" in prop and prop.get("type") == "number":
                flags["needs_math"] = True
            items = prop.get("items", {})
            if isinstance(items, dict):
                if "multipleOf" in items and items.get("type") == "number":
                    flags["needs_math"] = True
    return flags


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


def _warn_unsupported_props(node, path: str = "") -> None:
    """Print a warning for every property whose schema degrades to a raw
    JSON fragment for a reason the schema author may not expect
    ($ref, union types, missing type, unsupported array items, out-of-range
    integer bounds).  Deliberately dynamic objects (additionalProperties
    without fixed properties) are not warned about."""
    if not isinstance(node, dict):
        return
    if node.get("type") == "object" and "properties" in node:
        for key, prop in sorted(node["properties"].items()):
            ppath = f"{path}.{key}" if path else key
            if not isinstance(prop, dict):
                continue
            desc = _infer_c_type(prop)
            if desc["kind"] == "dynamic" and not _is_dynamic_object(prop):
                if "$ref" in prop:
                    reason = "$ref is not resolved"
                elif isinstance(prop.get("type"), list):
                    reason = "union types are not supported"
                elif "type" not in prop:
                    reason = "no 'type' keyword"
                elif prop.get("type") == "array":
                    reason = "unsupported array item type"
                elif prop.get("type") == "integer":
                    reason = "integer bounds exceed the 64-bit range"
                else:
                    reason = "unsupported construct"
                print(
                    f"  warning: property {ppath!r}: {reason}; "
                    "the value is stored as a raw JSON fragment",
                    file=sys.stderr)
            _warn_unsupported_props(prop, ppath)
    elif node.get("type") == "array" and isinstance(node.get("items"), dict):
        _warn_unsupported_props(node["items"], path + "[]")
    for defs_key in ("$defs", "definitions"):
        for dname, dnode in sorted(node.get(defs_key, {}).items()):
            _warn_unsupported_props(
                dnode, f"{path}#{dname}" if path else f"#{dname}")


def generate_unmarshal_h(scopes: list, pfx: str, sub_schema: bool = False) -> list:
    lines = []
    root_scope = scopes[0][0]
    for scope_name, keys, node in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        lines += [
            f"/**",
            f" * @brief Unmarshal JSON into *obj; modifies @p json in place.",
            f" * @param obj Output; zeroed and given schema defaults before parsing.",
            f" * @param json Mutable JSON; @p obj aliases it, so keep it valid in use.",
            f" * @param length Length of @p json in bytes.",
            f" * @return true on success; on failure, false and *obj reset to all-zero.",
            f" */",
            f"bool {make_fn_name('unmarshal', scope_name, pfx)}(",
            f"{_INDENT}struct {ename} *obj, char *json, size_t length);",
            "",
        ]
    return lines


def _gen_unmarshal_array_string_helper(
        scope_name: str, pfx: str, fname: str, item_checks: list = None,
        max_items: "int | None" = None) -> list:
    ic = item_checks or []
    ename = _ext(scope_name, pfx)
    # The helper name lives in the same identifier space as nested-object
    # unmarshal functions; embed "_arr_" in the suffix to disambiguate,
    # because a field name can collide with a nested object scope name.
    fn_name = make_fn_name("unmarshal", scope_name, pfx, suffix=f"arr_{fname}")
    max_check = [] if max_items is None else [
        f"{_INDENT * 2}if (count_ >= {max_items}u) {{ free(items_); return false; }}",
    ]
    return [
        f"static bool {fn_name}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        f"{{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, &(size_t){{ val_len_ }});",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}struct json_string *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}int next_;",
        f"{_INDENT}while ((next_ = json_arr_next(val_, &val_len_, &ait_, &av_, &alen_)) == JSON_NEXT_ITEM) {{",
    ] + max_check + [
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
        f"{_INDENT * 3}struct json_string *na_ = realloc(items_, nc_ * sizeof(*na_));",
        f"{_INDENT * 3}if (na_ == NULL) {{",
        f"{_INDENT * 4}free(items_);",
        f"{_INDENT * 4}return false;",
        f"{_INDENT * 3}}}",
        f"{_INDENT * 3}items_ = na_; cap_ = nc_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}if (!json_parse_string(av_, alen_, &items_[count_].str, &items_[count_].len)) {{",
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
        f"{_INDENT}obj->{fname}_count = count_;",
        f"{_INDENT}return true;",
        f"}}",
        "",
    ]


def _gen_unmarshal_array_object_helper(
        scope_name: str, pfx: str, fname: str, child_scope: str,
        max_items: "int | None" = None) -> list:
    ename = _ext(scope_name, pfx)
    child_ename = _ext(child_scope, pfx)
    child_free = make_fn_name("free", child_scope, pfx)
    # The helper name lives in the same identifier space as nested-object
    # unmarshal functions; embed "_arr_" in the suffix to disambiguate,
    # because a field name can collide with a nested object scope name.
    fn_name = make_fn_name("unmarshal", scope_name, pfx, suffix=f"arr_{fname}")
    max_check = [] if max_items is None else [
        f"{_INDENT * 2}if (count_ >= {max_items}u) {{ goto fail_; }}",
    ]
    return [
        f"static bool {fn_name}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        f"{{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, &(size_t){{ val_len_ }});",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}struct {child_ename} *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}int next_;",
        f"{_INDENT}while ((next_ = json_arr_next(val_, &val_len_, &ait_, &av_, &alen_)) == JSON_NEXT_ITEM) {{",
    ] + max_check + [
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
        f"{_INDENT * 3}struct {child_ename} *na_ = realloc(items_, nc_ * sizeof(*na_));",
        f"{_INDENT * 3}if (na_ == NULL) {{ goto fail_; }}",
        f"{_INDENT * 3}items_ = na_; cap_ = nc_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}if (!{make_fn_name('unmarshal', child_scope, pfx)}(&items_[count_], av_, alen_)) {{",
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
        f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{",
        f"{_INDENT * 3}{child_free}(&obj->{fname}[i_]);",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}free(obj->{fname});",
        f"{_INDENT}}}",
        f"{_INDENT}obj->{fname} = items_;",
        f"{_INDENT}obj->{fname}_count = count_;",
        f"{_INDENT}return true;",
        f"",
        f"fail_:",
        f"{_INDENT}for (size_t i_ = 0; i_ < count_; i_++) {{",
        f"{_INDENT * 2}{child_free}(&items_[i_]);",
        f"{_INDENT}}}",
        f"{_INDENT}free(items_);",
        f"{_INDENT}return false;",
        f"}}",
        "",
    ]


def _gen_unmarshal_array_primitive_helper(
        scope_name: str, pfx: str, fname: str, c_base: str,
        item_checks: list = None, max_items: "int | None" = None) -> list:
    ic = item_checks or []
    ename = _ext(scope_name, pfx)
    # The helper name lives in the same identifier space as nested-object
    # unmarshal functions; embed "_arr_" in the suffix to disambiguate,
    # because a field name can collide with a nested object scope name.
    fn_name = make_fn_name("unmarshal", scope_name, pfx, suffix=f"arr_{fname}")
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
        f"{_INDENT * 2}if (count_ >= {max_items}u) {{ free(items_); return false; }}",
    ]
    return [
        f"static bool {fn_name}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        f"{{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, &(size_t){{ val_len_ }});",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}{c_base} *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}int next_;",
        f"{_INDENT}while ((next_ = json_arr_next(val_, &val_len_, &ait_, &av_, &alen_)) == JSON_NEXT_ITEM) {{",
    ] + max_check + [
        f"{_INDENT * 2}{c_base} pv_;",
        f"{_INDENT * 2}if (!{parse_fn}(av_, alen_, &pv_)) {{ free(items_); return false; }}",
    ] + ic + [
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
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
        f"{_INDENT}obj->{fname}_count = count_;",
        f"{_INDENT}return true;",
        f"}}",
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
    # Emit innermost scopes first so child unmarshal functions are defined
    # before any parent function that calls them.
    for scope_name, keys, node in reversed(scopes):
        ename = _ext(scope_name, pfx)
        required = _required_set(node)
        storage = "" if sub_schema or scope_name == root_scope else "static "
        fname_map = _make_field_map(keys, node)

        # --- static helpers for array fields (emitted before the unmarshal function) ---
        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            kind = desc["kind"]
            fname = fname_map[key]
            max_items = prop.get("maxItems") if validate else None
            if max_items is not None:
                max_items = int(max_items)
            if kind == "array_string":
                item_checks = []
                if validate:
                    item_schema = prop.get("items", {})
                    if item_schema:
                        item_checks = _scalar_constraint_checks(
                            item_schema, "string", {
                                "kind": "string", "c_type": ""},
                            f"items_[count_]", _INDENT * 2,
                            "free(items_); return false;")
                lines += _gen_unmarshal_array_string_helper(
                    scope_name, pfx, fname, item_checks, max_items)
            elif kind == "array_object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                lines += _gen_unmarshal_array_object_helper(
                    scope_name, pfx, fname, child_scope, max_items)
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
                                _INDENT * 2, "free(items_); return false;")
                lines += _gen_unmarshal_array_primitive_helper(
                    scope_name, pfx, fname, c_base, item_checks, max_items)

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
            f"{{",
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
            f"{_INDENT}if (root_.type != JSON_OBJECT) {{ return false; }}",
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
            enum_val = ename.upper() + "_" + fname_map[key].upper()
            seen_line = [
                f"{_INDENT * 3}required_ |= UINT64_C(1) << {req_bit[key]};",
            ] if validate and key in required else []

            lines.append(f"{_INDENT * 2}case {enum_val}: {{")
            if kind == "string":
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;") if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_string(val_, val_len_, &obj->{fname}.str, &obj->{fname}.len)) {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "int":
                c_type = desc.get("c_type", "intmax_t")
                fn = "json_parse_int" if c_type == "int" else "json_parse_imax"
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;") if validate else []
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
                    "goto fail_;") if validate else []
                lines += [
                    f"{_INDENT * 3}if (!{fn}(val_, val_len_, &obj->{fname})) {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "double":
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;") if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_double(val_, val_len_, &obj->{fname})) {{ goto fail_; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "bool":
                cchks = _scalar_constraint_checks(
                    prop, kind, desc, f"obj->{fname}", _INDENT * 3,
                    "goto fail_;") if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_bool(val_, val_len_, &obj->{fname})) {{ goto fail_; }}",
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
                    f"{_INDENT * 3}if (!{make_fn_name('unmarshal', child_scope, pfx)}(&obj->{fname}, val_, val_len_)) {{",
                    f"{_INDENT * 4}goto fail_;",
                    f"{_INDENT * 3}}}",
                ] + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "dynamic":
                lines += [
                    f"{_INDENT * 3}obj->{fname}_json.str = val_;",
                    f"{_INDENT * 3}obj->{fname}_json.len = val_len_;",
                ] + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind in ("array_string", "array_object", "array_primitive"):
                achks = []
                if validate:
                    # maxItems is enforced inside the helper loop (rejecting
                    # oversized input before it is fully buffered); only
                    # minItems needs a post-parse check.
                    min_items = prop.get("minItems")
                    if min_items is not None:
                        achks.append(
                            f"{_INDENT * 3}if (obj->{fname}_count < {int(min_items)}u) {{ goto fail_; }}")
                lines += [
                    f"{_INDENT * 3}if (!{make_fn_name('unmarshal', scope_name, pfx, suffix=f'arr_{fname}')
                                         }(obj, val_, val_len_)) {{ goto fail_; }}",
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
            f"",
            f"fail_:",
            f"{_INDENT}{make_fn_name('free', scope_name, pfx)}(obj);",
            f"{_INDENT}*obj = (struct {ename}){{ 0 }};",
            f"{_INDENT}return false;",
            f"}}",
            "",
        ]

    return lines


def generate_marshal_h(scopes: list, pfx: str, sub_schema: bool = False) -> list:
    lines = []
    root_scope = scopes[0][0]
    for scope_name, _, _ in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        lines += [
            f"/**",
            f" * @brief Marshal *obj into @p buf as JSON (snprintf semantics).",
            f" * @param buf Output buffer, or NULL to only compute the size.",
            f" * @param bufsz Size of @p buf in bytes.",
            f" * @param obj Object to encode.",
            f" * @param indent Per-level indent for pretty output, or NULL for compact.",
            f" * @return Byte length excluding NUL (truncates if >= @p bufsz), or -1 on error.",
            f" */",
            f"int {make_fn_name('marshal', scope_name, pfx)}(",
            f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj, const char *indent);",
            "",
        ]
    return lines


def generate_marshal_c(
        scopes: list, pfx: str, schema_pfx: str,
        sub_schema: bool = False) -> list:
    """Generate marshal functions that write JSON text directly to a buffer.

    Each function uses snprintf semantics: returns the length required to
    encode *obj (excluding the terminating NUL) regardless of bufsz; the
    output is NUL-terminated whenever buf != NULL and bufsz > 0 and is
    truncated when the return value >= bufsz.  Returns -1 on error (e.g. a
    non-finite double, which has no JSON representation).

    The EMIT* macros compute ``buf + n_`` only while ``n_ < bufsz``; once
    the output is past the end of the buffer they pass NULL/0 instead, so
    no out-of-bounds pointer is ever formed (pointer arithmetic beyond
    one-past-the-end is undefined behavior even if never dereferenced).
    """
    lines = [
        "#define EMIT(c) do { \\",
        f"{_INDENT}if (buf != NULL && (size_t)n_ < bufsz) {{ buf[n_] = (char)(c); }} \\",
        f"{_INDENT}n_++; \\",
        "} while (0)",
        "#define EMITF(fmt, ...) do { \\",
        f"{_INDENT}char *dst_ = (buf != NULL && (size_t)n_ < bufsz) ? buf + n_ : NULL; \\",
        f"{_INDENT}r_ = snprintf(dst_, dst_ != NULL ? bufsz - (size_t)n_ : 0, fmt, __VA_ARGS__); \\",
        f"{_INDENT}if (r_ < 0) {{ return -1; }} \\",
        f"{_INDENT}n_ += r_; \\",
        "} while (0)",
        "#define EMIT_STR(s, len) do { \\",
        f"{_INDENT}char *dst_ = (buf != NULL && (size_t)n_ < bufsz) ? buf + n_ : NULL; \\",
        f"{_INDENT}r_ = json_marshal_string(dst_, dst_ != NULL ? bufsz - (size_t)n_ : 0, (s), (len)); \\",
        f"{_INDENT}if (r_ < 0) {{ return -1; }} \\",
        f"{_INDENT}n_ += r_; \\",
        "} while (0)",
        "#define EMIT_SUB(fn, arg, d) do { \\",
        f"{_INDENT}char *dst_ = (buf != NULL && (size_t)n_ < bufsz) ? buf + n_ : NULL; \\",
        f"{_INDENT}r_ = (fn)(dst_, dst_ != NULL ? bufsz - (size_t)n_ : 0, (arg), indent, (d)); \\",
        f"{_INDENT}if (r_ < 0) {{ return -1; }} \\",
        f"{_INDENT}n_ += r_; \\",
        "} while (0)",
        "#define EMIT_LIT(s) do { \\",
        f"{_INDENT}static const char lit_[] = s; \\",
        f"{_INDENT}const size_t l_ = sizeof(lit_) - 1; \\",
        f"{_INDENT}if (buf != NULL && (size_t)n_ < bufsz) {{ \\",
        f"{_INDENT * 2}const size_t cap_ = bufsz - (size_t)n_; \\",
        f"{_INDENT * 2}memcpy(buf + n_, lit_, l_ < cap_ ? l_ : cap_); \\",
        f"{_INDENT}}} \\",
        f"{_INDENT}n_ += (int)l_; \\",
        "} while (0)",
        # EMIT_RAW writes a run of literal bytes (the indent string) verbatim,
        # without JSON escaping; used only for pretty-print whitespace.
        "#define EMIT_RAW(s, len) do { \\",
        f"{_INDENT}const size_t rl_ = (len); \\",
        f"{_INDENT}if (buf != NULL && (size_t)n_ < bufsz) {{ \\",
        f"{_INDENT * 2}const size_t cap_ = bufsz - (size_t)n_; \\",
        f"{_INDENT * 2}memcpy(buf + n_, (s), rl_ < cap_ ? rl_ : cap_); \\",
        f"{_INDENT}}} \\",
        f"{_INDENT}n_ += (int)rl_; \\",
        "} while (0)",
        # EMIT_INDENT writes a newline followed by (d) copies of the indent
        # string.  A NULL indent selects compact output: nothing is emitted.
        "#define EMIT_INDENT(d) do { \\",
        f"{_INDENT}if (indent != NULL) {{ \\",
        f"{_INDENT * 2}EMIT('\\n'); \\",
        f"{_INDENT * 2}for (int id_ = 0; id_ < (d); id_++) {{ EMIT_RAW(indent, ind_len_); }} \\",
        f"{_INDENT}}} \\",
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
        impl_name = make_fn_name("marshal", scope_name, pfx, suffix="impl")

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

        lines += [
            f"static int {impl_name}(",
            f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj,",
            f"{_INDENT}const char *indent, int depth)",
            f"{{",
            f"{_INDENT}int n_ = 0;",
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
            f"{_INDENT}const int n_start_ = n_;",
            "",
        ]

        for idx, (kind, fname, json_key, is_req) in enumerate(emit_fields):
            esc_key = _c_string_literal(_json_escape(json_key))[0]
            if kind == "todo":
                lines += [
                    f"{_INDENT}/* TODO: {fname} marshal not yet generated */",
                ]
                continue

            # Determine the condition under which this field is emitted.
            # Scalar types (bool/int/uint/double) have no NULL sentinel, so
            # they are always emitted regardless of value.
            # String/array/dynamic fields use NULL to represent "not present".
            # Object fields: required ones are always emitted; optional ones
            # use the first required string sub-field as a presence sentinel —
            # the same NULL-as-absent convention as strings.
            if kind == "string":
                cond = f"obj->{fname}.str != NULL"
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
                cond = f"obj->{fname}_json.str != NULL"
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
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT_STR(obj->{fname}.str, obj->{fname}.len);",
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
                    f"{_INDENT * 2}if (!isfinite(obj->{fname})) {{ return -1; }}",
                ] + key_prefix + [
                    f"{_INDENT * 2}EMITF(\"%.17g\", obj->{fname});",
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
                child_impl = make_fn_name(
                    "marshal", child_scope, pfx, suffix="impl")
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT_SUB({child_impl}, &obj->{fname}, depth + 1);",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "dynamic":
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMITF(\"%.*s\", (int)obj->{fname}_json.len, obj->{fname}_json.str);",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "array_string":
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT('[');",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{",
                    f"{_INDENT * 3}if (i_ > 0) EMIT(',');",
                    f"{_INDENT * 3}EMIT_INDENT(depth + 2);",
                    f"{_INDENT * 3}EMIT_STR(obj->{fname}[i_].str, obj->{fname}[i_].len);",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}if (obj->{fname}_count > 0) {{ EMIT_INDENT(depth + 1); }}",
                    f"{_INDENT * 2}EMIT(']');",
                    f"{_INDENT * 2}EMIT(',');",
                ]
            elif kind == "array_object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), json_key, schema_pfx)
                child_impl = make_fn_name(
                    "marshal", child_scope, pfx, suffix="impl")
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT('[');",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{",
                    f"{_INDENT * 3}if (i_ > 0) EMIT(',');",
                    f"{_INDENT * 3}EMIT_INDENT(depth + 2);",
                    f"{_INDENT * 3}EMIT_SUB({child_impl}, &obj->{fname}[i_], depth + 2);",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}if (obj->{fname}_count > 0) {{ EMIT_INDENT(depth + 1); }}",
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
                           "unsigned": "%u", "uintmax_t": "%ju"}.get(c_base, "%.17g")
                    elem_lines = [
                        f"{_INDENT * 3}if (i_ > 0) EMIT(',');",
                        f"{_INDENT * 3}EMIT_INDENT(depth + 2);",
                    ]
                    if c_base == "double":
                        elem_lines += [
                            f"{_INDENT * 3}/* NaN/Inf have no JSON representation */",
                            f"{_INDENT * 3}if (!isfinite(obj->{fname}[i_])) {{ return -1; }}",
                        ]
                    elem_lines += [
                        f"{_INDENT * 3}EMITF(\"{fmt}\", obj->{fname}[i_]);",
                    ]
                field_lines += key_prefix + [
                    f"{_INDENT * 2}EMIT('[');",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{",
                ] + elem_lines + [
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}if (obj->{fname}_count > 0) {{ EMIT_INDENT(depth + 1); }}",
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

        # Closing brace: strip the trailing comma left by the last emitted
        # field, then emit '}'; simpler and cheaper than tracking first_.
        # Finally NUL-terminate (snprintf semantics).  Nested EMIT_SUB calls
        # also write a NUL, but the parent's next EMIT overwrites it, so the
        # outermost terminator always lands last.
        # When any field was emitted, strip its trailing comma and break the
        # closing brace onto its own line aligned with this object's level
        # (EMIT_INDENT is a no-op in compact mode).  An empty object stays "{}".
        lines += [
            "",
            f"{_INDENT}if (n_ > n_start_) {{",
            f"{_INDENT * 2}n_--;",
            f"{_INDENT * 2}EMIT_INDENT(depth);",
            f"{_INDENT}}}",
            f"{_INDENT}EMIT('}}');",
            f"{_INDENT}if (buf != NULL && bufsz > 0) {{",
            f"{_INDENT * 2}buf[(size_t)n_ < bufsz ? (size_t)n_ : bufsz - 1] = '\\0';",
            f"{_INDENT}}}",
            "",
            f"{_INDENT}return n_;",
            f"}}",
            "",
        ]

        # Public entry point: a thin wrapper that starts recursion at depth 0.
        # The depth/recursion bookkeeping is kept out of the public signature,
        # which exposes only the indent string (NULL selects compact output).
        if is_public:
            storage = "" if sub_schema or scope_name == root_scope else "static "
            lines += [
                f"{storage}int {make_fn_name('marshal', scope_name, pfx)}(",
                f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj,",
                f"{_INDENT}const char *indent)",
                f"{{",
                f"{_INDENT}return {impl_name}(buf, bufsz, obj, indent, 0);",
                f"}}",
                "",
            ]
    lines += [
        "",
        "#undef EMIT",
        "#undef EMITF",
        "#undef EMIT_STR",
        "#undef EMIT_SUB",
        "#undef EMIT_LIT",
        "#undef EMIT_RAW",
        "#undef EMIT_INDENT",
        "#undef EMIT_COLON",
        "",
    ]
    return lines


# ---------------------------------------------------------------------------
# Top-level process function
# ---------------------------------------------------------------------------

def process(schema_path: Path, opts: argparse.Namespace) -> None:
    print("processing " + str(schema_path))
    with schema_path.open() as f:
        schema = json.load(f)
    schema = _canonicalize(schema)

    stem = schema_path.stem
    schema_pfx = stem[: -len("_schema")] if stem.endswith("_schema") else stem
    pfx = opts.prefix
    scopes = list(collect_scopes(schema, schema_pfx))
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

    # Warn about constructs that silently degrade to raw JSON fragments.
    _warn_unsupported_props(schema)

    do_structs = opts.do_structs
    do_unmarshal = opts.do_unmarshal
    do_marshal = opts.do_marshal
    do_lookup = opts.do_lookup

    guard = stem.upper() + "_GEN_H"
    h_path = schema_path.with_name(stem + ".gen.h")
    c_path = schema_path.with_name(stem + ".gen.c")

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
            fname_map = _make_field_map(keys, node)
            enum_members = [
                _INDENT
                + ename.upper()
                + "_"
                + fname_map[key].upper()
                + " = "
                + str(i)
                + ","
                for i, key in enumerate(keys)
            ]
            h_lines += (
                [
                    f"enum {ename}_key {{",
                ]
                + enum_members
                + [
                    "};",
                    f"/* Look up str (length len) in the {ename} {'lookup' if opts.optimize == 'size' else 'perfect-hash'} table; returns key index or -1. */",
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
    # ---- collect source includes -----------------------------------------
    c_sys_includes = set()
    if do_unmarshal or do_lookup:
        c_sys_includes.add("#include <string.h>")
    # stdlib.h: free/realloc (structs/unmarshal) and bsearch (size mode, or
    # the empty-key fallback in fast mode).
    if do_structs or do_unmarshal or do_lookup:
        c_sys_includes.add("#include <stdlib.h>")
    if do_marshal:
        c_sys_includes.add("#include <stdio.h>")
        c_sys_includes.add("#include <stdint.h>")
        # memcpy in EMIT_LIT
        c_sys_includes.add("#include <string.h>")
        if _has_double_fields(scopes):
            # isfinite guard on double fields
            c_sys_includes.add("#include <math.h>")
    if do_unmarshal and opts.validate:
        cflags = _schema_constraint_flags(scopes)
        if cflags["needs_math"]:
            c_sys_includes.add("#include <math.h>")
    c_proj_includes = set()
    if do_unmarshal or do_marshal:
        c_proj_includes.add('#include "' + opts.inc_pfx + 'json.h"')

    c_lines = [
        "/** @file " + c_path.name,
        " * Auto-generated by scripts/gen_schema.py from "
        + schema_path.name + " -- do not edit. */",
        '#include "' + h_path.name + '"',
        "",
    ] + (sorted(c_proj_includes) + [""] if c_proj_includes else []) + sorted(c_sys_includes) + (
        [""] if c_sys_includes else []
    )

    if do_lookup or do_unmarshal:
        c_lines += ["/** @name Key tables", " *  @{ */", ""]
        for scope_name, keys, _ in scopes:
            ename = _ext(scope_name, pfx)
            lookup_name = _lookup_root(pfx, scope_name)
            print("  " + ename + ": " + str(len(keys)) + " keys")
            c_src = _try_single_byte_lookup(
                lookup_name, keys, public_lookup=do_lookup)
            if c_src is None:
                use_bsearch = opts.optimize == "size"
                if not use_bsearch and not _gperf_safe_keys(keys):
                    print(
                        f"  note: {ename} has an empty key, which gperf "
                        "cannot index; using the bsearch lookup instead",
                        file=sys.stderr)
                    use_bsearch = True
                if use_bsearch:
                    c_src = _generate_bsearch_lookup_c(
                        lookup_name, keys, public_lookup=do_lookup)
                else:
                    c_src = _run_gperf(lookup_name, keys)
                    c_src = _postprocess_gperf(
                        c_src, lookup_name, public_lookup=do_lookup)
            c_lines += ["/* --- " + ename + " --- */", c_src]
        c_lines += ["/** @} */", ""]

        if not do_lookup:
            # Enum is not in the header; define it here so the unmarshal
            # callbacks can reference the key constants in switch/case.
            c_lines += ["/** @name Key indices", " *  @{ */", ""]
            for scope_name, keys, node in scopes:
                ename = _ext(scope_name, pfx)
                fname_map = _make_field_map(keys, node)
                enum_members = [
                    _INDENT
                    + ename.upper()
                    + "_"
                    + fname_map[key].upper()
                    + " = "
                    + str(i)
                    + ","
                    for i, key in enumerate(keys)
                ]
                c_lines += (
                    [f"enum {ename}_key {{"]
                    + enum_members
                    + ["};", ""]
                )
            c_lines += ["/** @} */", ""]

    if do_structs:
        c_lines += ["/** @name Free", " *  @{ */", ""]
        c_lines += generate_free_c(scopes, pfx, schema_pfx, opts.sub_schema)
        c_lines += ["/** @} */", ""]

    if do_unmarshal:
        c_lines += ["/** @name Unmarshal", " *  @{ */", ""]
        c_lines += generate_unmarshal_c(
            scopes, pfx, schema_pfx, opts.sub_schema, opts.validate,
            opts.strict)
        c_lines += ["/** @} */", ""]

    if do_marshal:
        c_lines += ["/** @name Marshal", " *  @{ */", ""]
        c_lines += generate_marshal_c(
            scopes, pfx, schema_pfx, opts.sub_schema)
        c_lines += ["/** @} */", ""]

    h_path.write_text("\n".join(h_lines))
    c_path.write_text("\n".join(c_lines))
    print("  wrote " + str(h_path))
    print("  wrote " + str(c_path))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
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
            "(struct types, functions, enums, lookup functions)"
        ),
    )
    parser.add_argument(
        "--optimize",
        metavar="MODE",
        choices=["fast", "size"],
        default="fast",
        help=(
            "fast (default): gperf perfect-hash for O(1) lookup; "
            "size: sorted table + memcmp binary search, no gperf dependency. "
            "Keys are emitted as quoted literals, so gperf handles arbitrary "
            "bytes; an empty key falls back to binary search."
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

    features = {f.strip() for f in opts.generate.split(",")}
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

    for arg in opts.schemas:
        process(Path(arg), opts)


if __name__ == "__main__":
    main()
