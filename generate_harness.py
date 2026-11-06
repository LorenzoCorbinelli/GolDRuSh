#!/usr/bin/env python3
"""
generate_harness.py
====================

Generates a libFuzzer/AFL++ harness (FuzzedDataProvider style) for a C/C++
library without a `main` function, starting from:

  1. the list of EXPORTED symbols from the library (extracted with `nm -D`,
     or manually provided with --names), and
  2. a JSON file with the TYPES of the arguments for each function, produced
     by your pyghidra module (type inference).

Expected type file format (both forms are supported):

    {
      "api1": ["int", "float"],
      "api2":  ["const char *", "int"]
    }

or, extended form with return type:

    {
      "api1": {"args": ["int", "float"], "ret": "void"},
      "api2":  {"args": ["const char *", "int"], "ret": "void"}
    }

Functions exported by the library but MISSING from the types file are SKIPPED
(with a warning), because without the signature it is impossible to generate a
valid call: better a known gap than a harness that causes UB.

Typical usage:

    python3 generate_harness.py \
        --lib ./libtarget.so \
        --types ./types_from_pyghidra.json \
        --out ./harness.cpp

    # or without a real library, manually specifying the names
    # (useful during testing/debugging of the generator):
    python3 generate_harness.py \
        --names api1,api2 \
        --types ./types_from_pyghidra.json \
        --out ./harness.cpp
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# --------------------------------------------------------------------------
# 1. Normalization and classification of C types
# --------------------------------------------------------------------------

INTEGRAL_TYPES = {
    "char": "char",
    "signed char": "signed char",
    "unsigned char": "unsigned char",
    "short": "short",
    "short int": "short",
    "unsigned short": "unsigned short",
    "unsigned short int": "unsigned short",
    "int": "int",
    "unsigned int": "unsigned int",
    "unsigned": "unsigned int",
    "long": "long",
    "long int": "long",
    "unsigned long": "unsigned long",
    "unsigned long int": "unsigned long",
    "long long": "long long",
    "long long int": "long long",
    "unsigned long long": "unsigned long long",
    "unsigned long long int": "unsigned long long",
    "size_t": "size_t",
    "ssize_t": "ssize_t",
    "int8_t": "int8_t",
    "uint8_t": "uint8_t",
    "int16_t": "int16_t",
    "uint16_t": "uint16_t",
    "int32_t": "int32_t",
    "uint32_t": "uint32_t",
    "int64_t": "int64_t",
    "uint64_t": "uint64_t",
}

FLOATING_TYPES = {"float": "float", "double": "double", "long double": "double"}
# long double -> treated as double: FDP does not have ConsumeFloatingPoint<long double>
# in a portable way across all versions; if you really need long double
# modify it here.

BOOL_TYPES = {"bool": "bool", "_Bool": "bool"}


@dataclass
class ParsedType:
    raw: str                       # original type, as-is (for the extern declaration)
    base: str                      # cleaned base type, without const/ptr/array
    pointer_depth: int = 0         # number of '*'
    array_len: Optional[int] = None  # if it's a fixed array like "char[32]"
    is_const: bool = False

    @property
    def is_pointer(self) -> bool:
        return self.pointer_depth > 0 or self.array_len is not None


def parse_c_type(type_str: str) -> ParsedType:
    """Performs a parsing (deliberately simple, not a full C parser) of
    a type string like 'const char *', 'uint8_t[16]', 'int', 'struct Foo *'.
    """
    s = type_str.strip()
    is_const = False

    # fixed array, e.g. "char[32]" or "char [32]"
    array_len = None
    m = re.search(r"\[\s*(\d+)\s*\]\s*$", s)
    if m:
        array_len = int(m.group(1))
        s = s[: m.start()].strip()

    # count and remove '*'
    pointer_depth = s.count("*")
    s = s.replace("*", "").strip()

    # remove 'const' (before or after the base type)
    tokens = s.split()
    tokens = [t for t in tokens if t != "const"]
    if len(tokens) != len(s.split()):
        is_const = True
    base = " ".join(tokens).strip()

    return ParsedType(
        raw=type_str.strip(),
        base=base,
        pointer_depth=pointer_depth,
        array_len=array_len,
        is_const=is_const,
    )


def classify(pt: ParsedType) -> str:
    """Returns a semantic category to guide code generation:
    'integral' | 'floating' | 'bool' | 'cstring' | 'out_scalar' | 'byte_array'
    | 'unknown_pointer' | 'unknown'
    """
    if pt.array_len is not None:
        # fixed byte/char array -> buffer
        if pt.base in ("char", "unsigned char", "uint8_t", "int8_t", "signed char"):
            return "byte_array"
        return "unknown"  # array of struct/other: we don't generate random content

    if pt.pointer_depth >= 2:
        return "unknown_pointer"  # pointer to pointer: too risky

    if pt.pointer_depth == 1:
        if pt.base in ("char",) :
            return "cstring"
        if pt.base in ("void",):
            return "unknown_pointer"
        if pt.base in INTEGRAL_TYPES or pt.base in FLOATING_TYPES or pt.base in BOOL_TYPES:
            return "out_scalar"  # pointer to known scalar -> likely out-param
        return "unknown_pointer"  # unknown struct/typedef

    # not pointer, not array
    if pt.base in INTEGRAL_TYPES:
        return "integral"
    if pt.base in FLOATING_TYPES:
        return "floating"
    if pt.base in BOOL_TYPES:
        return "bool"
    return "unknown"


# --------------------------------------------------------------------------
# 2. Generation of consumption code for a single argument
# --------------------------------------------------------------------------

@dataclass
class ArgPlan:
    index: int
    pt: ParsedType
    category: str
    var_name: str
    decl_lines: List[str] = field(default_factory=list)    # C++ declaration/consumption lines
    call_expr: str = ""                                    # expression to use in the call
    is_variable_length: bool = False
    warning: Optional[str] = None


MAX_FIXED_BUFFER_HINT = 64  # used as fallback for "void*" buffers if ever needed


def plan_argument(idx: int, type_str: str, max_string_len: int) -> ArgPlan:
    pt = parse_c_type(type_str)
    cat = classify(pt)
    var = f"arg{idx}"

    if cat == "integral":
        ctype = INTEGRAL_TYPES[pt.base]
        plan = ArgPlan(idx, pt, cat, var)
        plan.decl_lines = [f"{ctype} {var} = fdp.ConsumeIntegral<{ctype}>();"]
        plan.call_expr = var
        return plan

    if cat == "floating":
        ctype = FLOATING_TYPES[pt.base]
        plan = ArgPlan(idx, pt, cat, var)
        plan.decl_lines = [f"{ctype} {var} = fdp.ConsumeFloatingPoint<{ctype}>();"]
        plan.call_expr = var
        return plan

    if cat == "bool":
        plan = ArgPlan(idx, pt, cat, var)
        plan.decl_lines = [f"bool {var} = fdp.ConsumeBool();"]
        plan.call_expr = var
        return plan

    if cat == "cstring":
        plan = ArgPlan(idx, pt, cat, var, is_variable_length=True)
        # the body (decl_lines) is filled later, in build_function_plan,
        # because it depends on whether it is the LAST variable field or not.
        # call_expr depends on the pointer's constancy:
        #   - "const char *" -> .c_str() (always returns const char*, it's fine)
        #   - "char *"       -> .data()  (in C++17 non-const std::string::data() 
        #                                  returns a mutable and null-terminated 
        #                                  buffer; .c_str() instead would lose 
        #                                  the const qualifier and would not compile)
        if pt.is_const:
            plan.call_expr = f"{var}.c_str()"
        else:
            plan.call_expr = f"{var}.data()"
        return plan

    if cat == "byte_array":
        n = pt.array_len
        plan = ArgPlan(idx, pt, cat, var)
        elem_t = pt.base
        plan.decl_lines = [
            f"std::vector<{elem_t}> {var} = fdp.ConsumeBytes<{elem_t}>({n});",
            f"{var}.resize({n});  // pad with 0 if the input wasn't enough",
        ]
        plan.call_expr = f"{var}.data()"
        return plan

    if cat == "out_scalar":
        base_ctype = (
            INTEGRAL_TYPES.get(pt.base)
            or FLOATING_TYPES.get(pt.base)
            or BOOL_TYPES.get(pt.base)
        )
        plan = ArgPlan(idx, pt, cat, var)
        if pt.base in INTEGRAL_TYPES:
            consume = f"fdp.ConsumeIntegral<{base_ctype}>()"
        elif pt.base in FLOATING_TYPES:
            consume = f"fdp.ConsumeFloatingPoint<{base_ctype}>()"
        else:
            consume = "fdp.ConsumeBool()"
        plan.decl_lines = [f"{base_ctype} {var} = {consume};  // pointer used as out-param"]
        plan.call_expr = f"&{var}"
        return plan

    # 'unknown_pointer' or 'unknown' -> we don't invent content
    plan = ArgPlan(idx, pt, "unknown_pointer", var)
    cast = pt.raw if pt.raw.strip() else "void *"
    plan.decl_lines = [
        f"// TODO: type '{pt.raw}' not handled automatically (pointer to struct/unknown "
        f"type or pointer to pointer).",
        f"// Passing nullptr to avoid random dereference: the function should probably",
        f"// be skipped or the block should be written manually (e.g., allocate and populate the struct).",
        f"{cast} {var} = nullptr;",
    ]
    plan.call_expr = var
    plan.warning = f"type not handled automatically: '{pt.raw}' -> passing nullptr"
    return plan


@dataclass
class FunctionPlan:
    name: str
    arg_plans: List[ArgPlan]
    ret_type: str
    warnings: List[str] = field(default_factory=list)


def build_function_plan(name: str, arg_types: List[str], ret_type: str, max_string_len: int) -> FunctionPlan:
    plans = [plan_argument(i, t, max_string_len) for i, t in enumerate(arg_types)]

    # Locate the last variable-length argument (cstring): that one
    # will consume "the rest of the bytes"; any other cstrings before it
    # will use a random but limited length, to leave bytes for
    # subsequent arguments.
    var_len_indices = [p.index for p in plans if p.is_variable_length]
    last_var_len_idx = var_len_indices[-1] if var_len_indices else None

    for p in plans:
        if p.category == "cstring":
            if p.index == last_var_len_idx:
                p.decl_lines = [
                    f"std::string {p.var_name} = fdp.ConsumeRemainingBytesAsString();"
                ]
            else:
                p.decl_lines = [
                    f"std::string {p.var_name} = fdp.ConsumeRandomLengthString({max_string_len});"
                ]
            if not p.pt.is_const:
                p.decl_lines.append(
                    f"// {p.var_name} passed with .data() (not .c_str()) because the parameter "
                    f"is non-const 'char *': requires C++17 (non-const std::string::data())."
                )

    warnings = [p.warning for p in plans if p.warning]
    return FunctionPlan(name=name, arg_plans=plans, ret_type=ret_type or "void", warnings=warnings)


def render_case(fp: FunctionPlan, case_idx: int) -> str:
    lines = [f"        case {case_idx}: {{  // {fp.name}"]

    # 1. first consume all FIXED size arguments, then the
    #    VARIABLE length ones (strings), in the order they appear,
    #    so the "remaining bytes" consumption truly stays last.
    fixed = [p for p in fp.arg_plans if not p.is_variable_length]
    variable = [p for p in fp.arg_plans if p.is_variable_length]

    for p in fixed + variable:
        for l in p.decl_lines:
            lines.append(f"            {l}")

    call_args = ", ".join(p.call_expr for p in fp.arg_plans)
    call = f"{fp.name}({call_args});"
    if fp.ret_type and fp.ret_type != "void":
        lines.append(f"            volatile {fp.ret_type} __ret = {call}")
        lines.append("            (void)__ret;")
    else:
        lines.append(f"            {call}")

    lines.append("            break;")
    lines.append("        }")
    return "\n".join(lines)


def render_extern_decl(fp: FunctionPlan) -> str:
    arg_decls = ", ".join(p.pt.raw if p.pt.raw.strip() else "void" for p in fp.arg_plans) or "void"
    return f"    {fp.ret_type} {fp.name}({arg_decls});"


# --------------------------------------------------------------------------
# 3. Extraction of symbols exported by the library with nm
# --------------------------------------------------------------------------

def extract_exported_functions(lib_path: str) -> List[str]:
    """Uses `nm -D --defined-only` to get the exported CODE symbols
    (type 'T' or 'W' in the symbol column), which are the function candidates.
    """
    try:
        out = subprocess.check_output(
            ["nm", "-D", "--defined-only", lib_path],
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        print("ERROR: 'nm' command not found on the system.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: 'nm' failed on {lib_path}:\n{e.output}", file=sys.stderr)
        sys.exit(1)

    names = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        _addr, sym_type, sym_name = parts
        if sym_type in ("T", "W", "t", "w"):  # code functions (global or weak)
            names.append(sym_name)
    return names


# --------------------------------------------------------------------------
# 4. Loading types file (produced by the pyghidra module)
# --------------------------------------------------------------------------

def load_types_file(path: str):
    with open(path, "r") as f:
        data = json.load(f)

    normalized = {}
    for fname, val in data.items():
        if isinstance(val, list):
            normalized[fname] = {"args": val, "ret": "void"}
        elif isinstance(val, dict):
            normalized[fname] = {"args": val.get("args", []), "ret": val.get("ret", "void")}
        else:
            raise ValueError(f"Unrecognized format for function '{fname}' in types file")
    return normalized


# --------------------------------------------------------------------------
# 5. Complete harness file generation
# --------------------------------------------------------------------------

HARNESS_HEADER = """\
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>

// Header automatically generated by generate_harness.py
// Types source: {types_source}
// Target library: {lib_source}

#include "libfuzzer/FuzzedDataProvider.h"

extern "C" {{
{decls}
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    FuzzedDataProvider fdp(Data, Size);

    if (fdp.remaining_bytes() < 1) {{
        return 0;
    }}

    // 1 byte to choose which function to call
    uint8_t api_choice = fdp.ConsumeIntegral<uint8_t>() % {num_funcs};

    switch (api_choice) {{
{cases}
        default:
            break;
    }}

    return 0;
}}

int main(int argc, char **argv) {{
    if (argc < 2) return 0;

    size_t total_size = 0;
    for (int i = 1; i < argc; i++) {{
        total_size += strlen(argv[i]);
    }}

    if (total_size == 0) return 0;

    uint8_t *buffer = (uint8_t *)malloc(total_size);
    if (!buffer) return 1;

    size_t offset = 0;
    for (int i = 1; i < argc; i++) {{
        size_t len = strlen(argv[i]);
        memcpy(buffer + offset, argv[i], len);
        offset += len;
    }}

    LLVMFuzzerTestOneInput(buffer, total_size);

    free(buffer);
    return 0;
}}
"""


def generate_harness(
    exported_names: List[str],
    types: dict,
    max_string_len: int,
    lib_source: str,
    types_source: str,
) -> Tuple[str, List[str]]:
    warnings = []

    missing = [n for n in exported_names if n not in types]
    if missing:
        warnings.append(
            "Exported functions but WITHOUT types in the pyghidra file (skipped): "
            + ", ".join(sorted(missing))
        )

    usable_names = [n for n in exported_names if n in types]
    if not usable_names:
        print("ERROR: no exported function has matching types in the file. Nothing to generate.",
              file=sys.stderr)
        sys.exit(1)

    function_plans = []
    for name in usable_names:
        entry = types[name]
        fp = build_function_plan(name, entry["args"], entry.get("ret", "void"), max_string_len)
        function_plans.append(fp)
        for w in fp.warnings:
            warnings.append(f"[{name}] {w}")

    decls = "\n".join(render_extern_decl(fp) for fp in function_plans)
    cases = "\n".join(render_case(fp, i) for i, fp in enumerate(function_plans))

    harness = HARNESS_HEADER.format(
        decls=decls,
        cases=cases,
        num_funcs=len(function_plans),
        lib_source=lib_source,
        types_source=types_source,
    )
    return harness, warnings


# --------------------------------------------------------------------------
# 6. CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Generates a FuzzedDataProvider harness for a library without a main function, "
                    "starting from the exported symbols and a types file produced via pyghidra."
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--lib", help="Path to the library (.so) from which to extract exported symbols with nm")
    src.add_argument("--names", help="Comma-separated list of function names (alternative to --lib, useful for testing)")

    ap.add_argument("--types", required=True, help="Path to the JSON types file produced by the pyghidra module")
    ap.add_argument("--out", required=True, help="Path of the .cpp harness file to generate")
    ap.add_argument("--max-string-len", type=int, default=256,
                     help="Maximum length for 'intermediate' strings (not the last one) [default: 256]")

    args = ap.parse_args()

    if args.lib:
        exported = extract_exported_functions(args.lib)
        lib_source = args.lib
    else:
        exported = [n.strip() for n in args.names.split(",") if n.strip()]
        lib_source = "(names manually provided via --names)"

    types = load_types_file(args.types)

    harness, warnings = generate_harness(
        exported_names=exported,
        types=types,
        max_string_len=args.max_string_len,
        lib_source=lib_source,
        types_source=args.types,
    )

    with open(args.out, "w") as f:
        f.write(harness)

    print(f"Harness written to: {args.out}")
    print(f"Functions included: {len([n for n in exported if n in types])} / {len(exported)} exported")
    if warnings:
        print("\nWarnings:", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)


if __name__ == "__main__":
    main()
