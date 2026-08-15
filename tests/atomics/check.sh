#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set -euo pipefail

if (($# != 2)); then
    printf 'usage: %s OPT PASS_PLUGIN\n' "$0" >&2
    exit 2
fi

opt=$1
plugin=$2
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pass='function(bpf-lower-atomics)'
complete_pass="${pass},function(bpf-finalize-atomic-load-store)"

for profile in 5.15 6.9; do
    "${opt}" -load-pass-plugin="${plugin}" -bpf-target="${profile}" \
        --passes="${complete_pass}" "${root}/supported.ll" -disable-output

    while IFS='|' read -r fixture expected; do
        set +e
        output=$("${opt}" -load-pass-plugin="${plugin}" \
            -bpf-target="${profile}" --passes="${pass}" \
            "${root}/${fixture}" -disable-output 2>&1)
        status=$?
        set -e
        if ((status != 1)); then
            printf '%s on Linux %s exited %d instead of 1\n%s\n' \
                "${fixture}" "${profile}" "${status}" "${output}" >&2
            exit 1
        fi
        if [[ ${output} != *"${expected}"* ]]; then
            printf '%s on Linux %s missed diagnostic %q\n%s\n' \
                "${fixture}" "${profile}" "${expected}" "${output}" >&2
            exit 1
        fi
        if [[ ${output} == *'PLEASE submit a bug report'* ||
              ${output} == *'Stack dump:'* ]]; then
            printf '%s on Linux %s aborted instead of failing cleanly\n%s\n' \
                "${fixture}" "${profile}" "${output}" >&2
            exit 1
        fi
    done <<'CASES'
unsupported-rmw.ll|Capsule atomic add i8 in unsupported_rmw cannot be preserved
unsupported-cmpxchg.ll|Capsule atomic compare-exchange i32 in unsupported_cmpxchg cannot be preserved
unsupported-order.ll|Capsule atomic load i32 in unsupported_order cannot be preserved
unsupported-misaligned.ll|Capsule atomic load i32 in unsupported_misaligned cannot be preserved
unsupported-fence.ll|Capsule atomic fence in unsupported_fence cannot be preserved
CASES
done

printf 'ATOMIC-CONTRACT-PASS\n'
