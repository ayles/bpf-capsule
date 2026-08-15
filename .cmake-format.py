# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
with section("parse"):
    additional_commands = {
        "bpf_capsule_bitcode": {
            "pargs": 1,
            "kwargs": {
                "SOURCES": "+",
                "DEPENDS": "*",
                "INCLUDE_DIRECTORIES": "*",
                "COMPILE_DEFINITIONS": "*",
                "COMPILE_OPTIONS": "*",
                "C_OPTIONS": "*",
                "CXX_OPTIONS": "*",
            },
        },
        "bpf_capsule_object": {
            "pargs": 1,
            "kwargs": {
                "OUTPUT": 1,
                "LINKED_BC": 1,
                "OPTIMIZED_BC": 1,
                "BITCODE": "+",
                "DEPENDS": "*",
                "RUNTIME_COMPILE_DEFINITIONS": "*",
            },
        },
        "bpf_capsule_runtime_bitcode": {
            "pargs": 1,
            "kwargs": {"COMPILE_DEFINITIONS": "*"},
        },
        "bpf_capsule_rust_bitcode": {
            "pargs": 1,
            "flags": ["LOCKED", "NO_DEFAULT_FEATURES"],
            "kwargs": {
                "MANIFEST_PATH": 1,
                "PACKAGE": 1,
                "FEATURES": "*",
                "DEPENDS": "*",
                "RUSTFLAGS": "*",
            },
        },
        "bpf_capsule_skeleton": {
            "pargs": 1,
            "kwargs": {
                "OUTPUT": 1,
                "OBJECT": 1,
                "NAME": 1,
                "DEPENDS": "*",
            },
        },
    }

with section("format"):
    line_width = 100
    tab_size = 4
    dangle_parens = True
    always_wrap = [
        "bpf_capsule_bitcode",
        "bpf_capsule_object",
        "bpf_capsule_rust_bitcode",
        "bpf_capsule_runtime_bitcode",
        "bpf_capsule_skeleton",
    ]

with section("markup"):
    enable_markup = False
