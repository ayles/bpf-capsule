# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Run the standalone Google Benchmark suite against the host kernel and merge
# its JSON files for the CI history. It is a runnable package rather than a
# check because it needs the real host kernel and root.
{
  writeShellApplication,
  coreutils,
  jq,
  util-linux,
  suite,
}:
writeShellApplication {
  name = "benchmarks";
  runtimeInputs = [
    coreutils
    jq
    util-linux
  ];
  text = ''
    if (( $# > 1 )); then
      echo "usage: benchmarks [OUTPUT.json]" >&2
      exit 2
    fi
    output="''${1:-benchmark-results/all.json}"
    scratch=$(mktemp -d)
    trap 'rm -r "$scratch"' EXIT
    artifact=${suite}
    for name in smoke_benchmark lua_benchmark overhead_benchmark; do
      sudo taskset -c 0 env \
        BPF_CAPSULE_LUA_SCRIPT="$artifact/libexec/bpf-capsule/benchmarks/lua-script.lua" \
        "$artifact/libexec/bpf-capsule/benchmarks/$name" \
        --benchmark_min_time=0.1s \
        --benchmark_out="$scratch/$name.json" \
        --benchmark_out_format=json
    done
    mkdir -p "$(dirname "$output")"
    jq -s '.[0] * {benchmarks: (map(.benchmarks) | add)}' \
      "$scratch"/*_benchmark.json > "$output"
    echo "$output"
  '';
}
