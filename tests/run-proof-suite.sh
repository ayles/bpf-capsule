#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=${1:-build-demo}
if (($#)); then
    shift
fi
if [[ ! -f ${build}/CMakeCache.txt ]]; then
    printf 'not a configured build directory: %s\n' "${build}" >&2
    exit 2
fi
build=$(cd -- "${build}" && pwd)

profile=$(sed -n 's/^BPF_CAPSULE_TARGET_KERNEL:STRING=//p' "${build}/CMakeCache.txt")
if [[ -z ${profile} ]]; then
    printf 'cannot determine BPF_CAPSULE_TARGET_KERNEL from %s/CMakeCache.txt\n' \
        "${build}" >&2
    exit 2
fi

# Real checkpoints remain caller-supplied, but the normal proof command must
# execute both llama implementations rather than merely prove they compile.
# Generate tiny valid fixtures unless the caller set either variable. Setting
# a variable to "none" deliberately skips that case.
fixture_dir=${build}/generated-fixtures
if [[ -z ${LLAMA2_MODEL+x} || -z ${LLAMA2Q_MODEL+x} ]]; then
    mapfile -t generated_models < <(
        python3 "${root}/tools/generate-llama-fixtures.py" "${fixture_dir}")
    if [[ -z ${LLAMA2_MODEL+x} ]]; then
        LLAMA2_MODEL=${generated_models[0]}
    fi
    if [[ -z ${LLAMA2Q_MODEL+x} ]]; then
        LLAMA2Q_MODEL=${generated_models[1]}
    fi
fi
if [[ ${LLAMA2_MODEL:-} == none ]]; then unset LLAMA2_MODEL; fi
if [[ ${LLAMA2Q_MODEL:-} == none ]]; then unset LLAMA2Q_MODEL; fi
export LLAMA2_MODEL LLAMA2Q_MODEL

exec python3 "${root}/benchmarks/regression.py" \
    --build "${build}" \
    --profile "${profile}" \
    --samples 1 \
    --no-build \
    --output "${build}/bpf-capsule-proof.json" \
    "$@"
