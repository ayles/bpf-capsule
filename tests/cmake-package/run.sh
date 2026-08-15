#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Manual smoke test for the installed CMake package: prove that
# find_package(BpfCapsule) resolves and drives the complete pipeline.
#
#   tests/cmake-package/run.sh [PREFIX]
#
# With PREFIX, the smoke project is configured and built against that
# existing BPF Capsule installation. Without arguments, the current source
# tree is first built and installed into a temporary prefix. Either way the
# smoke project must configure, build, and produce smoke.bpf.o. The script then
# builds the public standalone example against the same prefix and executes it
# in BPF. Run from an environment providing the toolchain (for example
# `nix develop`).
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d -t bpf-capsule-package-smoke.XXXXXX)
keep=1
cleanup() {
    if ((keep)); then
        printf 'Work tree kept for debugging: %s\n' "${work}" >&2
    else
        rm -rf -- "${work}"
    fi
}
trap cleanup EXIT

if (($# > 0)); then
    prefix=$(cd -- "$1" && pwd)
else
    prefix=${work}/prefix
    cmake -S "${root}" -B "${work}/build" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${prefix}"
    cmake --build "${work}/build" -j "$(nproc)"
    cmake --install "${work}/build"
fi

cmake -S "${root}/tests/cmake-package" -B "${work}/smoke" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="${prefix}"
cmake --build "${work}/smoke" -j "$(nproc)"
test -s "${work}/smoke/smoke.bpf.o"

if cmake -S "${root}/tests/cmake-package/invalid" -B "${work}/invalid" \
    -DCMAKE_PREFIX_PATH="${prefix}" >"${work}/invalid.log" 2>&1; then
    printf 'unknown CMake helper argument unexpectedly configured\n' >&2
    exit 1
fi
if ! grep -Fq 'received unknown arguments: TYPO' "${work}/invalid.log"; then
    cat "${work}/invalid.log" >&2
    exit 1
fi

if cmake -S "${root}/tests/cmake-package" -B "${work}/invalid-fibers" \
    -DCMAKE_PREFIX_PATH="${prefix}" -DBPF_CAPSULE_MAX_FIBERS=65536 \
    >"${work}/invalid-fibers.log" 2>&1; then
    printf 'out-of-range compiled fiber ceiling unexpectedly configured\n' >&2
    exit 1
fi
if ! grep -Fq 'must be an integer from 1 to 65535 or empty' \
    "${work}/invalid-fibers.log"; then
    cat "${work}/invalid-fibers.log" >&2
    exit 1
fi

cmake -S "${root}/examples/standalone" -B "${work}/standalone" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="${prefix}"
cmake --build "${work}/standalone" -j "$(nproc)"

run=()
if ((EUID != 0)); then
    if ! command -v sudo >/dev/null; then
        printf 'standalone BPF execution needs root; sudo was not found\n' >&2
        exit 1
    fi
    run=(sudo)
fi
"${run[@]}" "${work}/standalone/expr"

keep=0
printf 'CMAKE-PACKAGE-SMOKE-PASS\n'
