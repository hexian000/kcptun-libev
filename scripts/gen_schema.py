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
                         size: sorted table + strncmp binary search;
                         smaller binary, no gperf dependency.

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
    if ident and ident[0].isdigit():
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
        minimum = prop_schema.get("minimum")
        maximum = prop_schema.get("maximum")
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


def _make_gperf_input(ext_scope: str, keys: list) -> str:
    header_lines = [
        "%language=ANSI-C",
        "%struct-type",
        "%readonly-tables",
        f"%define hash-function-name {ext_scope}_hash",
        f"%define lookup-function-name {ext_scope}_kv_lookup_",
        "%define slot-name name",
        "%{",
        f"/* {ext_scope}: {len(keys)} keys  (auto-generated -- do not edit) */",
        "%}",
        "struct " + ext_scope + "_kv { int name; int idx; };",
        "%%",
    ]
    keyword_lines = [f"{key}, {i}" for i, key in enumerate(keys)]
    return "\n".join(header_lines) + "\n" + "\n".join(keyword_lines) + "\n%%\n"


def _run_gperf(ext_scope: str, keys: list) -> str:
    src = _make_gperf_input(ext_scope, keys)
    try:
        r = subprocess.run(
            ["gperf", "-l", "-c", "-E", "-P",
             f"-Q{ext_scope}_stringpool", "--null-strings",
             "--initializer-suffix=,0"],
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
                 repr(ext_scope) + ":\n" + e.stderr)


def _postprocess_gperf(
        src: str, ext_scope: str, public_lookup: bool = True) -> str:
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
    - Append a thin ``int {ext_scope}_lookup(...)`` wrapper.  When
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
    kv_ret = "const struct " + ext_scope + "_kv *\n"
    result = ["static " + ln if ln == kv_ret else ln for ln in result]

    # Suppress -Wunused-parameter on the hash function's `str` argument.
    patched = []
    hash_sig = ext_scope + "_hash"
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
        ext_scope + "_lookup(const char *str, size_t len)\n",
        "{\n",
        _INDENT + "const struct " + ext_scope + "_kv *kv_ = "
        + ext_scope + "_kv_lookup_(str, len);\n",
        _INDENT + "return kv_ ? kv_->idx : -1;\n",
        "}\n",
    ]
    return "".join(result)


def _generate_bsearch_lookup_c(
        ext_scope: str, keys: list, public_lookup: bool) -> str:
    """Generate a bsearch(3)-based lookup (--optimize size).

    Keys are sorted by (length, name) so the comparator can prune with a
    cheap integer comparison before calling memcmp.
    Requires <stdlib.h> (bsearch) and <string.h> (memcmp).
    """
    tbl = f"{ext_scope}_keys_"
    entry_t = f"{ext_scope}_entry_"
    n = len(keys)
    storage = "" if public_lookup else "static "
    # Sort entries by (length, name) for the table; record the original index
    # so the returned idx still matches the enum values assigned in key order.
    sorted_entries = sorted(enumerate(keys), key=lambda x: (len(x[1].encode("utf-8")), x[1]))
    result = [
        f"typedef struct {{ const char *name; size_t len; int idx; }} {entry_t};",
        f"static const {entry_t} {tbl}[] = {{",
    ]
    for orig_i, key in sorted_entries:
        c_key_esc, c_key_len = _c_string_literal(key)
        result.append(f'{_INDENT}{{"{c_key_esc}", {c_key_len}, {orig_i}}},')
    result += [
        f"}};",
        f"static int {ext_scope}_cmp_(const void *key_, const void *entry_)",
        f"{{",
        f"{_INDENT}const {entry_t} *k_ = (const {entry_t} *)key_;",
        f"{_INDENT}const {entry_t} *e_ = (const {entry_t} *)entry_;",
        f"{_INDENT}if (k_->len < e_->len) {{ return -1; }}",
        f"{_INDENT}if (k_->len > e_->len) {{ return  1; }}",
        f"{_INDENT}return memcmp(k_->name, e_->name, k_->len);",
        f"}}",
        f"{storage}int",
        f"{ext_scope}_lookup(const char *str, size_t len)",
        f"{{",
        f"{_INDENT}const {entry_t} key_ = {{str, len, 0}};",
        f"{_INDENT}const {entry_t} *e_ =",
        f"{_INDENT * 2}bsearch(&key_, {tbl}, {n}, sizeof(*{tbl}), {ext_scope}_cmp_);",
        f"{_INDENT}return e_ ? e_->idx : -1;",
        f"}}",
        "",
    ]
    return "\n".join(result)


def _c_char_escape(c: str) -> str:
    """Escape a single character for use in a C char literal."""
    if c == "\\":
        return "\\\\"
    if c == "'":
        return "\\'"
    if c == "\n":
        return "\\n"
    if c == "\r":
        return "\\r"
    if c == "\t":
        return "\\t"
    return c


# Sentinel for "no default present" — distinguishes missing from default=0/false/""
_MISSING = object()

# One indentation level for generated C source (four spaces).
_INDENT = "    "


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
            parts.append(f"\\x{byte:02x}")
    return "".join(parts), len(encoded)


def _default_designated_init(
        fname: str, kind: str, desc: dict, default_val,
        indent: str = _INDENT * 2) -> "str | None":
    """Return a C designated-initializer string for a struct field default, or None."""
    if kind == "bool":
        return f"{indent}.{fname} = {'true' if default_val else 'false'},"
    if kind == "int":
        n = int(default_val)
        c_type = desc.get("c_type", "intmax_t")
        lit = f"INTMAX_C({n})" if c_type == "intmax_t" else str(n)
        return f"{indent}.{fname} = {lit},"
    if kind == "uint":
        n = int(default_val)
        c_type = desc.get("c_type", "uintmax_t")
        lit = f"UINTMAX_C({n})" if c_type == "uintmax_t" else f"{n}u"
        return f"{indent}.{fname} = {lit},"
    if kind == "double":
        c_val = f"{default_val}.0" if isinstance(default_val, int) else repr(float(default_val))
        return f"{indent}.{fname} = {c_val},"
    if kind == "string" and isinstance(default_val, str):
        escaped, byte_len = _c_string_literal(default_val)
        return f"{indent}.{fname} = {{ .str = \"{escaped}\", .len = {byte_len} }},"
    return None


def _collect_object_defaults(
        scope_name: str, schema_pfx: str, scopes_map: dict,
        indent: str = _INDENT * 2) -> list:
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
        ext_scope: str, keys: list, public_lookup: bool) -> "str | None":
    """Return C source for a single-byte switch lookup, or None.

    Scans byte positions 0..min_key_len-1.  The first position where every
    key has a distinct character becomes the switch discriminator, avoiding
    the need for gperf.  Each case performs a full-length memcmp to confirm
    the match, so the result is correct even when two keys share a prefix.
    """
    if not keys:
        return None
    min_len = min(len(k) for k in keys)
    for pos in range(min_len):
        chars = [k[pos] for k in keys]
        if len(set(chars)) < len(keys):
            continue
        storage = "" if public_lookup else "static "
        lines = [
            f"{storage}int",
            f"{ext_scope}_lookup(const char *str, size_t len)",
            "{",
            f"{_INDENT}if (len < {pos + 1}) {{ return -1; }}",
            f"{_INDENT}switch ((unsigned char)str[{pos}]) {{",
        ]
        for i, key in enumerate(keys):
            c_char = _c_char_escape(key[pos])
            c_key_esc, c_key_len = _c_string_literal(key)
            lines.append(f"{_INDENT}case '{c_char}':")
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
    """Return the external symbol name for a scope by prepending the user prefix.

    Applies uniformly to struct tags, function names, enum names, lookup
    functions, and enum-value prefixes.
    """
    return pfx + scope_name


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

    Layout per struct:
      1. All ``bool`` bitfields (``has_*`` presence flags followed by boolean
         value fields) at the top, each group sorted alphabetically.  Keeping
         all bitfields contiguous lets the compiler pack them into a single
         word.
      2. Remaining fields grouped by C type (objects, strings, arrays,
         dynamic JSON fragments, unsigned integers, signed integers, doubles),
         sorted alphabetically within each group.
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
            f"/* Free heap-allocated fields inside *obj (arrays). */",
            f"void {ename}_free(struct {ename} *obj);",
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
        lines.append(f"{storage}void {ename}_free(struct {ename} *obj)")
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
                    f"{_INDENT}{_ext(child_scope, pfx)}_free(&obj->{fname});")
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
                    f"{_INDENT * 3}{child_ename}_free(&obj->{fname}[i_]);")
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
    """
    lines = []
    c_type = desc.get("c_type", "")

    if kind == "string":
        str_expr = f"{val_expr}.str"
        len_expr = f"{val_expr}.len"
        min_len  = prop_schema.get("minLength")
        max_len  = prop_schema.get("maxLength")
        const_v  = prop_schema.get("const")
        enum_vs  = prop_schema.get("enum")

        if min_len is not None:
            lines.append(f"{indent}if ({len_expr} < {min_len}u) {{ {fail_stmt} }}")
        if max_len is not None:
            lines.append(f"{indent}if ({len_expr} > {max_len}u) {{ {fail_stmt} }}")

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
        minimum  = prop_schema.get("minimum")
        maximum  = prop_schema.get("maximum")
        excl_min = prop_schema.get("exclusiveMinimum")
        excl_max = prop_schema.get("exclusiveMaximum")
        mult_of  = prop_schema.get("multipleOf")
        const_v  = prop_schema.get("const")
        enum_vs  = prop_schema.get("enum")

        # Skip minimum <= 0 for unsigned types — the parser already rejects negatives.
        if minimum is not None and not (is_unsigned and minimum <= 0):
            lines.append(f"{indent}if ({val_expr} < {_c_num_literal(minimum, kind, c_type)}) {{ {fail_stmt} }}")
        if maximum is not None:
            lines.append(f"{indent}if ({val_expr} > {_c_num_literal(maximum, kind, c_type)}) {{ {fail_stmt} }}")
        if excl_min is not None and not (is_unsigned and excl_min < 0):
            lines.append(f"{indent}if ({val_expr} <= {_c_num_literal(excl_min, kind, c_type)}) {{ {fail_stmt} }}")
        if excl_max is not None:
            lines.append(f"{indent}if ({val_expr} >= {_c_num_literal(excl_max, kind, c_type)}) {{ {fail_stmt} }}")
        if mult_of is not None:
            lines.append(f"{indent}if ({val_expr} % {_c_num_literal(mult_of, kind, c_type)} != 0) {{ {fail_stmt} }}")
        if const_v is not None:
            lines.append(f"{indent}if ({val_expr} != {_c_num_literal(const_v, kind, c_type)}) {{ {fail_stmt} }}")
        if enum_vs is not None and len(enum_vs) > 0:
            conds = " && ".join(f"{val_expr} != {_c_num_literal(v, kind, c_type)}" for v in enum_vs)
            lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    elif kind == "double":
        minimum  = prop_schema.get("minimum")
        maximum  = prop_schema.get("maximum")
        excl_min = prop_schema.get("exclusiveMinimum")
        excl_max = prop_schema.get("exclusiveMaximum")
        mult_of  = prop_schema.get("multipleOf")
        const_v  = prop_schema.get("const")
        enum_vs  = prop_schema.get("enum")

        if minimum  is not None: lines.append(f"{indent}if ({val_expr} < {_c_num_literal(minimum, 'double', '')}) {{ {fail_stmt} }}")
        if maximum  is not None: lines.append(f"{indent}if ({val_expr} > {_c_num_literal(maximum, 'double', '')}) {{ {fail_stmt} }}")
        if excl_min is not None: lines.append(f"{indent}if ({val_expr} <= {_c_num_literal(excl_min, 'double', '')}) {{ {fail_stmt} }}")
        if excl_max is not None: lines.append(f"{indent}if ({val_expr} >= {_c_num_literal(excl_max, 'double', '')}) {{ {fail_stmt} }}")
        if mult_of  is not None: lines.append(f"{indent}if (fmod({val_expr}, {_c_num_literal(mult_of, 'double', '')}) != 0.0) {{ {fail_stmt} }}")
        if const_v  is not None: lines.append(f"{indent}if ({val_expr} != {_c_num_literal(const_v, 'double', '')}) {{ {fail_stmt} }}")
        if enum_vs  is not None and len(enum_vs) > 0:
            conds = " && ".join(f"{val_expr} != {_c_num_literal(v, 'double', '')}" for v in enum_vs)
            lines.append(f"{indent}if ({conds}) {{ {fail_stmt} }}")

    elif kind == "bool":
        const_v = prop_schema.get("const")
        enum_vs = prop_schema.get("enum")

        if const_v is not None:
            lines.append(f"{indent}if ({val_expr} != {'true' if const_v else 'false'}) {{ {fail_stmt} }}")
        if enum_vs is not None and len(enum_vs) > 0:
            valid = ["true" if v else "false" for v in enum_vs if isinstance(v, bool)]
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


def generate_unmarshal_h(scopes: list, pfx: str, sub_schema: bool = False) -> list:
    lines = []
    root_scope = scopes[0][0]
    for scope_name, keys, node in scopes:
        if not sub_schema and scope_name != root_scope:
            continue
        ename = _ext(scope_name, pfx)
        lines += [
            f"/* Unmarshal json (length bytes) into *obj; the buffer is modified in-place. */",
            f"/* The function zero-initializes *obj and applies schema defaults before parsing; pointer fields of set keys then point into the json buffer (keep it valid). Returns true on success. */",
            f"bool {ename}_unmarshal(",
            f"{_INDENT}struct {ename} *obj, char *json, size_t length);",
            "",
        ]
    return lines


def _gen_unmarshal_array_string_helper(ename: str, fname: str, item_checks: list = None) -> list:
    ic = item_checks or []
    return [
        f"static bool {ename}_unmarshal_{fname}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        f"{{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, val_len_);",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}struct json_string *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}while (json_arr_next(val_, val_len_, &ait_, &av_, &alen_)) {{",
        f"{_INDENT * 2}const struct json_val sv_ = json_parse(av_, alen_);",
        f"{_INDENT * 2}if (sv_.type != JSON_STRING) {{",
        f"{_INDENT * 3}free(items_);",
        f"{_INDENT * 3}return false;",
        f"{_INDENT * 2}}}",
    ] + ic + [
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
        f"{_INDENT * 3}struct json_string *na_ = realloc(items_, nc_ * sizeof(*na_));",
        f"{_INDENT * 3}if (na_ == NULL) {{",
        f"{_INDENT * 4}free(items_);",
        f"{_INDENT * 4}return false;",
        f"{_INDENT * 3}}}",
        f"{_INDENT * 3}items_ = na_; cap_ = nc_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}items_[count_].str = sv_.str;",
        f"{_INDENT * 2}items_[count_].len = sv_.len;",
        f"{_INDENT * 2}count_++;",
        f"{_INDENT}}}",
        f"{_INDENT}if (count_ == 0) {{",
        f"{_INDENT * 2}items_ = malloc(sizeof(*items_));",
        f"{_INDENT * 2}if (!items_) {{ return false; }}",
        f"{_INDENT}}}",
        f"{_INDENT}obj->{fname} = items_;",
        f"{_INDENT}obj->{fname}_count = count_;",
        f"{_INDENT}return true;",
        f"}}",
        "",
    ]


def _gen_unmarshal_array_object_helper(ename: str, fname: str, child_ename: str) -> list:
    return [
        f"static bool {ename}_unmarshal_{fname}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        f"{{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, val_len_);",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}struct {child_ename} *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}while (json_arr_next(val_, val_len_, &ait_, &av_, &alen_)) {{",
        f"{_INDENT * 2}if (count_ >= cap_) {{",
        f"{_INDENT * 3}const size_t nc_ = cap_ ? cap_ * 2 : 4;",
        f"{_INDENT * 3}struct {child_ename} *na_ = realloc(items_, nc_ * sizeof(*na_));",
        f"{_INDENT * 3}if (na_ == NULL) {{",
        f"{_INDENT * 4}for (size_t i_ = 0; i_ < count_; i_++) {{",
        f"{_INDENT * 5}{child_ename}_free(&items_[i_]);",
        f"{_INDENT * 4}}}",
        f"{_INDENT * 4}free(items_);",
        f"{_INDENT * 4}return false;",
        f"{_INDENT * 3}}}",
        f"{_INDENT * 3}items_ = na_; cap_ = nc_;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}memset(&items_[count_], 0, sizeof(items_[count_]));",
        f"{_INDENT * 2}if (!{child_ename}_unmarshal(&items_[count_], av_, alen_)) {{",
        f"{_INDENT * 3}{child_ename}_free(&items_[count_]);",
        f"{_INDENT * 3}for (size_t i_ = 0; i_ < count_; i_++) {{",
        f"{_INDENT * 4}{child_ename}_free(&items_[i_]);",
        f"{_INDENT * 3}}}",
        f"{_INDENT * 3}free(items_);",
        f"{_INDENT * 3}return false;",
        f"{_INDENT * 2}}}",
        f"{_INDENT * 2}count_++;",
        f"{_INDENT}}}",
        f"{_INDENT}if (count_ == 0) {{",
        f"{_INDENT * 2}items_ = malloc(sizeof(*items_));",
        f"{_INDENT * 2}if (!items_) {{ return false; }}",
        f"{_INDENT}}}",
        f"{_INDENT}obj->{fname} = items_;",
        f"{_INDENT}obj->{fname}_count = count_;",
        f"{_INDENT}return true;",
        f"}}",
        "",
    ]


def _gen_unmarshal_array_primitive_helper(ename: str, fname: str, c_base: str, item_checks: list = None) -> list:
    ic = item_checks or []
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
    return [
        f"static bool {ename}_unmarshal_{fname}(",
        f"{_INDENT}struct {ename} *obj, char *val_, size_t val_len_)",
        f"{{",
        f"{_INDENT}const struct json_val arr_ = json_parse(val_, val_len_);",
        f"{_INDENT}if (arr_.type != JSON_ARRAY) {{ return false; }}",
        f"{_INDENT}{c_base} *items_ = NULL;",
        f"{_INDENT}size_t count_ = 0, cap_ = 0;",
        f"{_INDENT}json_iter ait_ = arr_.iter;",
        f"{_INDENT}char *av_; size_t alen_;",
        f"{_INDENT}while (json_arr_next(val_, val_len_, &ait_, &av_, &alen_)) {{",
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
        f"{_INDENT}if (count_ == 0) {{",
        f"{_INDENT * 2}items_ = malloc(sizeof(*items_));",
        f"{_INDENT * 2}if (!items_) {{ return false; }}",
        f"{_INDENT}}}",
        f"{_INDENT}obj->{fname} = items_;",
        f"{_INDENT}obj->{fname}_count = count_;",
        f"{_INDENT}return true;",
        f"}}",
        "",
    ]


def generate_unmarshal_c(scopes: list, pfx: str, schema_pfx: str, sub_schema: bool = False, validate: bool = True) -> list:
    """Generate a pull-parse unmarshal function for every scope.

    Design
    ------
    * Uses the pull-parse API: json_parse + json_obj_next to iterate object
      keys and dispatch to per-field handlers.
    * No callbacks, no context structs — a single while loop with a switch.
    * Nested object fields: call the child's unmarshal directly on the raw
      value fragment (modifying it in-place; the outer iterator has already
      advanced past that fragment).
    * Dynamic-key object fields: strndup the raw fragment before any
      in-place decoding; the caller walks it later with json_parse +
      json_obj_next on the heap copy.
    * Array-of-string fields: parse the raw array fragment in-place, collect
      (ptr, len) pairs that point into the caller's json buffer; no heap
      allocation per element.
    * Scalar string fields: parse the raw fragment in-place; obj->field
      is a json_string that points into the caller's json buffer.
    * Numeric/bool values: parse the raw fragment in-place.
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
            if kind == "array_string":
                item_checks = []
                if validate:
                    item_schema = prop.get("items", {})
                    if item_schema:
                        item_checks = _scalar_constraint_checks(
                            item_schema, "string", {"kind": "string", "c_type": ""},
                            "sv_", _INDENT * 2, "free(items_); return false;")
                lines += _gen_unmarshal_array_string_helper(ename, fname, item_checks)
            elif kind == "array_object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                child_ename = _ext(child_scope, pfx)
                lines += _gen_unmarshal_array_object_helper(
                    ename, fname, child_ename)
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
                    ename, fname, c_base, item_checks)

        # --- unmarshal function ---
        lines += [
            f"{storage}bool {ename}_unmarshal(",
            f"{_INDENT}struct {ename} *obj, char *json, size_t length)",
            f"{{",
            f"{_INDENT}const struct json_val root_ = json_parse(json, length);",
            f"{_INDENT}if (root_.type != JSON_OBJECT) {{ return false; }}",
            f"{_INDENT}json_iter iter_ = root_.iter;",
            f"{_INDENT}char *key_; size_t key_len_; char *val_; size_t val_len_;",
        ]

        # --- zero-init + defaults via a single compound literal ---
        # Recursively collects defaults for nested object fields too: when a
        # child object key is absent from the input JSON the compound literal
        # ensures its fields receive the schema-defined default values.
        designated = _collect_object_defaults(scope_name, schema_pfx, scopes_map)
        if designated:
            lines.append(f"{_INDENT}*obj = (struct {ename}){{")
            lines += designated
            lines.append(f"{_INDENT}}};")
        else:
            lines.append(f"{_INDENT}*obj = (struct {ename}){{ 0 }};")
        n_required = sum(1 for k in required if k in keys)
        if validate and n_required:
            lines.append(f"{_INDENT}int required_ = {n_required};")
        lines.append("")

        lines += [
            f"{_INDENT}while (json_obj_next(json, length, &iter_,",
            f"{_INDENT * 3}&key_, &key_len_, &val_, &val_len_)) {{",
            f"{_INDENT * 2}const int k_ = {ename}_lookup(key_, key_len_);",
            f"{_INDENT * 2}switch (k_) {{",
        ]

        for key in keys:
            prop = node["properties"][key]
            desc = _infer_c_type(prop)
            kind = desc["kind"]
            fname = fname_map[key]
            enum_val = ename.upper() + "_" + fname_map[key].upper()
            seen_line = [f"{_INDENT * 3}required_--;"] if validate and key in required else []

            lines.append(f"{_INDENT * 2}case {enum_val}: {{")
            if kind == "string":
                cchks = _scalar_constraint_checks(prop, kind, desc, f"obj->{fname}", _INDENT * 3) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_string(val_, val_len_, &obj->{fname}.str, &obj->{fname}.len)) {{ return false; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "int":
                c_type = desc.get("c_type", "intmax_t")
                fn = "json_parse_int" if c_type == "int" else "json_parse_imax"
                cchks = _scalar_constraint_checks(prop, kind, desc, f"obj->{fname}", _INDENT * 3) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!{fn}(val_, val_len_, &obj->{fname})) {{ return false; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "uint":
                c_type = desc.get("c_type", "uintmax_t")
                fn = "json_parse_uint" if c_type == "unsigned" else "json_parse_umax"
                cchks = _scalar_constraint_checks(prop, kind, desc, f"obj->{fname}", _INDENT * 3) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!{fn}(val_, val_len_, &obj->{fname})) {{ return false; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "double":
                cchks = _scalar_constraint_checks(prop, kind, desc, f"obj->{fname}", _INDENT * 3) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_double(val_, val_len_, &obj->{fname})) {{ return false; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "bool":
                cchks = _scalar_constraint_checks(prop, kind, desc, f"obj->{fname}", _INDENT * 3) if validate else []
                lines += [
                    f"{_INDENT * 3}if (!json_parse_bool(val_, val_len_, &obj->{fname})) {{ return false; }}",
                ] + cchks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            elif kind == "object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), key, schema_pfx)
                child_ename = _ext(child_scope, pfx)
                lines += [
                    f"{_INDENT * 3}if (!{child_ename}_unmarshal(&obj->{fname}, val_, val_len_)) {{",
                    f"{_INDENT * 4}return false;",
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
                    min_items = prop.get("minItems")
                    max_items = prop.get("maxItems")
                    if min_items is not None:
                        achks.append(f"{_INDENT * 3}if (obj->{fname}_count < {min_items}u) {{ return false; }}")
                    if max_items is not None:
                        achks.append(f"{_INDENT * 3}if (obj->{fname}_count > {max_items}u) {{ return false; }}")
                lines += [
                    f"{_INDENT * 3}if (!{ename}_unmarshal_{fname}(obj, val_, val_len_)) {{ return false; }}",
                ] + achks + seen_line + [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]
            else:
                lines += [
                    f"{_INDENT * 3}break;",
                    f"{_INDENT * 2}}}",
                ]

        lines += [
            f"{_INDENT * 2}default:",
            f"{_INDENT * 3}break;",
            f"{_INDENT * 2}}}",
            f"{_INDENT}}}",
        ]

        # Required field checks after the loop.
        # When validation is enabled, verify that all required fields were
        # present; required_ was initialised to the total count and
        # decremented for each field encountered.
        if validate and n_required:
            lines.append(f"{_INDENT}if (required_) {{ return false; }}")

        lines += [
            f"{_INDENT}return true;",
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
            f"/* Marshal *obj into buf as JSON text (snprintf semantics: returns chars written",
            f"   excluding NUL, or required size including NUL when buf is NULL or bufsz is 0). */",
            f"int {ename}_marshal(char *buf, size_t bufsz, const struct {ename} *obj);",
            "",
        ]
    return lines


def generate_marshal_c(
        scopes: list, pfx: str, schema_pfx: str,
        sub_schema: bool = False) -> list:
    """Generate marshal functions that write JSON text directly to a buffer.

    Each function uses snprintf semantics: returns the number of characters
    written (excluding NUL), or the required buffer size (including NUL) when
    buf is NULL or bufsz is 0.  A two-pass approach is used internally when
    the caller does not supply a buffer.
    """
    lines = [
        "#define EMIT(fmt, ...) do { \\",
        f"{_INDENT}r_ = snprintf(buf ? buf + n_ : NULL, \\",
        f"{_INDENT * 2}bufsz > (size_t)n_ ? bufsz - (size_t)n_ : 0, fmt, __VA_ARGS__); \\",
        f"{_INDENT}if (r_ < 0) {{ return -1; }} \\",
        f"{_INDENT}n_ += r_; \\",
        "} while (0)",
        "#define EMIT_STR(s, len) do { \\",
        f"{_INDENT}r_ = json_marshal_string(buf ? buf + n_ : NULL, \\",
        f"{_INDENT * 2}bufsz > (size_t)n_ ? bufsz - (size_t)n_ : 0, (s), (len)); \\",
        f"{_INDENT}if (r_ < 0) {{ return -1; }} \\",
        f"{_INDENT}n_ += r_; \\",
        "} while (0)",
        "#define EMIT_SUB(fn, arg) do { \\",
        f"{_INDENT}r_ = (fn)(buf ? buf + n_ : NULL, \\",
        f"{_INDENT * 2}bufsz > (size_t)n_ ? bufsz - (size_t)n_ : 0, (arg)); \\",
        f"{_INDENT}if (r_ < 0) {{ return -1; }} \\",
        f"{_INDENT}n_ += r_; \\",
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
        storage = "" if sub_schema or scope_name == root_scope else "static "
        fname_map = _make_field_map(keys, node)

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
            f"{storage}int {ename}_marshal(",
            f"{_INDENT}char *buf, size_t bufsz, const struct {ename} *obj)",
            f"{{",
            f"{_INDENT}int n_ = 0;",
            f"{_INDENT}int r_;",
            "",
        ]

        # Opening brace; record n_ after '{' for trailing-comma removal.
        lines += [
            f"{_INDENT}EMIT(\"%s\", \"{{\");",
            f"{_INDENT}const int n_start_ = n_;",
            "",
        ]

        for idx, (kind, fname, json_key, is_req) in enumerate(emit_fields):
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
                cond = f"obj->{fname} != NULL"
            else:
                cond = None

            # Build the block that emits this field using EMIT / EMIT_STR /
            # EMIT_SUB macros defined at the top of the marshal section.
            # Every path appends a trailing ','; the closing-brace block
            # strips the last one before emitting '}'.
            field_lines = []

            if kind == "string":
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":\", \"{json_key}\");",
                    f"{_INDENT * 2}EMIT_STR(obj->{fname}.str, obj->{fname}.len);",
                    f"{_INDENT * 2}EMIT(\"%s\", \",\");",
                ]
            elif kind == "int":
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":%jd,\", \"{json_key}\",",
                    f"{_INDENT * 3}(intmax_t)obj->{fname});",
                ]
            elif kind == "uint":
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":%ju,\", \"{json_key}\",",
                    f"{_INDENT * 3}(uintmax_t)obj->{fname});",
                ]
            elif kind == "double":
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":%.17g,\", \"{json_key}\",",
                    f"{_INDENT * 3}obj->{fname});",
                ]
            elif kind == "bool":
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":%s,\", \"{json_key}\",",
                    f"{_INDENT * 3}obj->{fname} ? \"true\" : \"false\");",
                ]
            elif kind == "object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), json_key, schema_pfx)
                child_ename = _ext(child_scope, pfx)
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":\", \"{json_key}\");",
                    f"{_INDENT * 2}EMIT_SUB({child_ename}_marshal, &obj->{fname});",
                    f"{_INDENT * 2}EMIT(\"%s\", \",\");",
                ]
            elif kind == "dynamic":
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":%.*s,\", \"{json_key}\",",
                    f"{_INDENT * 3}(int)obj->{fname}_json.len, obj->{fname}_json.str);",
                ]
            elif kind == "array_string":
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":[\", \"{json_key}\");",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{",
                    f"{_INDENT * 3}if (i_ > 0) {{ if (buf && bufsz > (size_t)n_) buf[n_] = ','; n_++; }}",
                    f"{_INDENT * 3}EMIT_STR(obj->{fname}[i_].str, obj->{fname}[i_].len);",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}EMIT(\"%s\", \"],\");",
                ]
            elif kind == "array_object":
                child_scope = _scope_of_child(
                    _path_from_scope(scope_name, schema_pfx), json_key, schema_pfx)
                child_ename = _ext(child_scope, pfx)
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":[\", \"{json_key}\");",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{",
                    f"{_INDENT * 3}if (i_ > 0) {{ if (buf && bufsz > (size_t)n_) buf[n_] = ','; n_++; }}",
                    f"{_INDENT * 3}EMIT_SUB({child_ename}_marshal, &obj->{fname}[i_]);",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}EMIT(\"%s\", \"],\");",
                ]
            elif kind == "array_primitive":
                prop_schema = node["properties"][json_key]
                prim_desc = _infer_c_type(prop_schema)
                c_base = prim_desc.get("c_base", "int")
                if c_base == "bool":
                    elem_fmt = "\"%s%s\""
                    elem_args = f"i_ > 0 ? \",\" : \"\", obj->{fname}[i_] ? \"true\" : \"false\""
                elif c_base == "int":
                    elem_fmt = "\"%s%d\""
                    elem_args = f"i_ > 0 ? \",\" : \"\", obj->{fname}[i_]"
                elif c_base == "intmax_t":
                    elem_fmt = "\"%s%jd\""
                    elem_args = f"i_ > 0 ? \",\" : \"\", obj->{fname}[i_]"
                elif c_base == "unsigned":
                    elem_fmt = "\"%s%u\""
                    elem_args = f"i_ > 0 ? \",\" : \"\", obj->{fname}[i_]"
                elif c_base == "uintmax_t":
                    elem_fmt = "\"%s%ju\""
                    elem_args = f"i_ > 0 ? \",\" : \"\", obj->{fname}[i_]"
                else:  # double
                    elem_fmt = "\"%s%.17g\""
                    elem_args = f"i_ > 0 ? \",\" : \"\", obj->{fname}[i_]"
                field_lines += [
                    f"{_INDENT * 2}EMIT(\"\\\"%s\\\":[\", \"{json_key}\");",
                    f"{_INDENT * 2}for (size_t i_ = 0; i_ < obj->{fname}_count; i_++) {{",
                    f"{_INDENT * 3}EMIT({elem_fmt}, {elem_args});",
                    f"{_INDENT * 2}}}",
                    f"{_INDENT * 2}EMIT(\"%s\", \"],\");",
                ]

            # Wrap in condition if needed
            if cond is not None:
                lines.append(f"{_INDENT}if ({cond}) {{")
                lines += field_lines
                lines.append(f"{_INDENT}}}")
            else:
                # Always emit — strip leading indentation
                for fl in field_lines:
                    lines.append(fl[len(_INDENT):] if fl.startswith(_INDENT) else fl)

        # Closing brace: strip the trailing comma left by the last emitted
        # field, then emit '}'; simpler and cheaper than tracking first_.
        lines += [
            "",
            f"{_INDENT}if (n_ > n_start_) {{ n_--; }}",
            f"{_INDENT}EMIT(\"%s\", \"}}\");",
            "",
            f"{_INDENT}return n_;",
            f"}}",
            "",
        ]
    lines += [
        "",
        "#undef EMIT",
        "#undef EMIT_STR",
        "#undef EMIT_SUB",
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
    ] + sorted(h_sys_includes) + [""] + (sorted(h_proj_includes) + [""] if h_proj_includes else [])

    if do_lookup:
        h_lines += ["/** @name Key tables", " *  @{ */", ""]
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
            h_lines += (
                [
                    f"enum {ename}_key {{",
                ]
                + enum_members
                + [
                    "};",
                    f"/* Look up str (length len) in the {ename} {'lookup' if opts.optimize == 'size' else 'perfect-hash'} table; returns key index or -1. */",
                    f"int {ename}_lookup(const char *str, size_t len);",
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
    if do_structs or do_unmarshal or (opts.optimize == "size" and do_lookup):
        c_sys_includes.add("#include <stdlib.h>")
    if do_marshal:
        c_sys_includes.add("#include <stdio.h>")
        c_sys_includes.add("#include <stdint.h>")
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
            print("  " + ename + ": " + str(len(keys)) + " keys")
            c_src = _try_single_byte_lookup(
                ename, keys, public_lookup=do_lookup)
            if c_src is None:
                if opts.optimize == "size":
                    c_src = _generate_bsearch_lookup_c(
                        ename, keys, public_lookup=do_lookup)
                else:
                    c_src = _run_gperf(ename, keys)
                    c_src = _postprocess_gperf(
                        c_src, ename, public_lookup=do_lookup)
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
            scopes, pfx, schema_pfx, opts.sub_schema, opts.validate)
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
            "size: sorted table + strncmp binary search, no gperf dependency."
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
            "Omit required-field validation from the generated unmarshal "
            "functions.  By default a uint64_t presence bitmask is used to "
            "verify every required field appeared in the JSON input, and the "
            "function returns false when any required field is absent."
        ),
    )
    opts = parser.parse_args()
    opts.validate = not opts.no_validate

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
