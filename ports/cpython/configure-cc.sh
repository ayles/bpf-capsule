#!/usr/bin/env bash
set -eu

: "${BPF_CAPSULE_CONFIGURE_CC:?}"
: "${BPF_CAPSULE_CONFIGURE_LD:?}"
: "${BPF_CAPSULE_CONFIGURE_LIBC:?}"
: "${BPF_CAPSULE_CONFIGURE_NM:?}"
: "${BPF_CAPSULE_CONFIGURE_SUPPORT:?}"

compile_only=0
for argument in "$@"; do
    case "$argument" in
        -c|-E|-S|-M|-MM|-M[DFGPT]*) compile_only=1 ;;
    esac
done
if ((compile_only)); then
    exec "$BPF_CAPSULE_CONFIGURE_CC" "$@"
fi
case "${1-}" in
    --version|-v|-V|-dumpmachine|-dumpversion|-print-*|-qversion)
        exec "$BPF_CAPSULE_CONFIGURE_CC" "$@"
        ;;
esac

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
output=a.out
inputs=()
flags=()
sources=()
skip_next=0
for argument in "$@"; do
    if ((skip_next)); then
        skip_next=0
        continue
    fi
    case "$argument" in
        -o) skip_next=1 ;;
        -o*) output=${argument#-o} ;;
        *.c|*.S|*.s) sources+=("$argument") ;;
        *.a|*.bc|*.o) inputs+=("$argument") ;;
        -l*|-L*|-Wl,*|-Xlinker|-shared|-pie|-static) ;;
        *) flags+=("$argument") ;;
    esac
done
for ((index = 1; index <= $#; ++index)); do
    if [[ ${!index} == -o ]]; then
        ((++index))
        output=${!index}
    fi
done

counter=0
for source in "${sources[@]}"; do
    bitcode="$temporary/$counter.bc"
    ((++counter)) || true
    "$BPF_CAPSULE_CONFIGURE_CC" "${flags[@]}" -c "$source" -o "$bitcode"
    inputs+=("$bitcode")
done
if ((${#inputs[@]} == 0)); then
    exit 1
fi

IFS=: read -r -a support <<<"$BPF_CAPSULE_CONFIGURE_SUPPORT"
"$BPF_CAPSULE_CONFIGURE_LD" --passes=no-op-module --emit-llvm -o "$output" \
    "${inputs[@]}" "${support[@]}" "$BPF_CAPSULE_CONFIGURE_LIBC"
# Unreferenced weak declarations may remain in the linked module; they are
# optional symbols, not failed link probes.
undefined=$("$BPF_CAPSULE_CONFIGURE_NM" --undefined-only "$output" | awk '$1 == "U" {print $2}' | grep -v '^__bpf_capsule_' || true)
if [[ -n $undefined ]]; then
    printf 'undefined reference(s): %s\n' "$undefined" >&2
    rm -f "$output"
    exit 1
fi
