# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Run every example package in a real kernel and pin its output: exact
# checksums, DOOM frame hashes, llama2 tokens against the native reference,
# and the continuation-drain count each workload is allowed.
{
  pkgs,
  examples,
  kernelPackages,
  profileKernel,
  disableDeviceTree ? false,
}:
let
  llamaModel = pkgs.fetchurl {
    url = "https://huggingface.co/karpathy/tinyllamas/resolve/0bd21da7698eaf29a0d7de3992de8a46ef624add/stories260K/stories260K.bin";
    hash = "sha256-sKUH560PYmYk8XESMl5maR+QdtYi4dMnTRA9ACmfJpY=";
  };
  llamaQ8Model = pkgs.runCommand "stories260K-q8.bin" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    ${pkgs.python3}/bin/python3 ${../../tests/vm/quantize-llama.py} ${llamaModel} "$out"
  '';
  llamaTokenizer = pkgs.fetchurl {
    url = "https://huggingface.co/karpathy/tinyllamas/resolve/0bd21da7698eaf29a0d7de3992de8a46ef624add/stories260K/tok512.bin";
    hash = "sha256-A3yzNauyXR+p6OyuMO0qOorOkwKGLrzcBdUaa7sQwxI=";
  };
  freedoomArchive = pkgs.fetchurl {
    url = "https://github.com/freedoom/freedoom/releases/download/v0.13.0/freedoom-0.13.0.zip";
    hash = "sha256-P5smTz485QO0+39r3LH0Gdk8e1RvTfPodN2Hjbloj1k=";
  };
  doomWad = pkgs.runCommand "bpf-capsule-freedoom1-wad" { nativeBuildInputs = [ pkgs.unzip ]; } ''
    mkdir -p "$out"
    unzip -p ${freedoomArchive} 'freedoom-0.13.0/freedoom1.wad' > "$out/freedoom1.wad"
    echo '7323bcc168c5a45ff10749b339960e98314740a734c30d4b9f3337001f9e703d  '"$out/freedoom1.wad" | sha256sum --check --status
  '';
in
import ./run.nix {
  inherit pkgs kernelPackages disableDeviceTree;
  name = "bpf-capsule-examples-profile-${profileKernel}-linux-${kernelPackages.kernel.version}";
  runtimeInputs = [
    pkgs.coreutils
    pkgs.iproute2 # veth pair and namespace for the Lua-XDP run
    pkgs.gnugrep
    pkgs.bpftools
    pkgs.jq
    pkgs.util-linux
  ];
  script = ''
    ulimit -l unlimited
    uname -a

    # run_example NAME MARKER DRAINS COMMAND...: the output must contain
    # MARKER; DRAINS is the exact continuation count, or - for "not checked".
    run_example() {
      local name="$1" marker="$2" drains="$3"
      shift 3
      printf 'RUN:%s\n' "$name"
      if example_output="$("$@" 2>&1)"; then
        :
      else
        status=$?
        printf '%s\n' "$example_output"
        printf '%s exited with status %s\n' "$name" "$status" >&2
        exit "$status"
      fi
      printf '%s\n' "$example_output"
      if [[ "$example_output" != *"$marker"* ]]; then
        printf '%s did not print %q\n' "$name" "$marker" >&2
        exit 1
      fi
      if [[ "$drains" != - && "$example_output" != *"continuation drains: $drains"* ]]; then
        printf '%s did not report %s continuation drains\n' "$name" "$drains" >&2
        exit 1
      fi
    }

    # run_native NAME COMMAND...: the same program with --native must print
    # exactly what the kernel run printed to stdout.
    run_native() {
      local name="$1"
      shift
      printf 'RUN:%s --native\n' "$name"
      "$@" > /tmp/kernel-stdout 2>/dev/null
      "$1" --native "''${@:2}" > /tmp/native-stdout 2>/tmp/native-stderr
      cat /tmp/native-stderr
      if ! cmp /tmp/kernel-stdout /tmp/native-stdout; then
        printf '%s: native output differs from the kernel output\n' "$name" >&2
        exit 1
      fi
      [[ "$(cat /tmp/native-stderr)" == *'native execution:'* ]]
    }

    run_example fib 'fib(20) = 6765' - ${examples.fib}/bin/fib
    run_example zlib 'stock zlib:' 0 ${examples.zlib}/bin/zlib 65536
    run_example sqlite $'500\t41791750' 0 \
      ${examples.sqlite}/bin/sqlite ${examples.sqlite}/share/bpf-capsule/sqlite/script.sql
    [[ "$example_output" == *'kernel execution:'* ]]
    run_native sqlite ${examples.sqlite}/bin/sqlite ${examples.sqlite}/share/bpf-capsule/sqlite/script.sql
    run_example wasm3 'stock zlib Wasm: 4096 ->' 0 ${examples.wasm3}/bin/wasm3 4096
    run_example lua $'Lua checksum\t16898\ttrue\t0\ttrue' 0 \
      ${examples.lua}/bin/lua ${../../examples/lua/script.lua}
    run_native lua ${examples.lua}/bin/lua ${../../examples/lua/script.lua}
    run_example quickjs 'checksum 807746 text-bytes 743 matches 100' 0 \
      ${examples.quickjs}/bin/quickjs ${../../examples/quickjs/script.js}
    run_native quickjs ${examples.quickjs}/bin/quickjs ${../../examples/quickjs/script.js}
    run_example rust 'Rust panic: status=exited code=101' 0 ${examples.rust}/bin/rust

    story='Once upon a time, there was a little girl named Lily. She loved to play outside in the park.'
    run_example llama2 "$story" 0 \
      ${examples.llama2}/bin/llama2 ${llamaModel} -z ${llamaTokenizer} -n 32 -t 0
    [[ "$example_output" == *'native reference: match'* ]]
    run_example llama2-q8 "$story" 0 \
      ${examples.llama2}/bin/llama2-q8 ${llamaQ8Model} -z ${llamaTokenizer} -n 32 -t 0
    [[ "$example_output" == *'native reference: match'* ]]

    expected=(
      a95d4cb55feeb7b3ef7c2bd289f32d1ce3105da4e91d71348eb1eaa6dc9adce2
      06553576c3d898219971710fce745457db31cfd76ae28d6c10ad72804d37d881
    )
    # The kernel and the native engine must draw the same two frames.
    for engine in kernel native; do
      mkdir -p "/tmp/doom-frames-$engine"
      native_flag=()
      [[ $engine == native ]] && native_flag=(--native)
      run_example "doom $engine" 'dump done: status=0' - \
        ${examples.doom}/bin/doom "''${native_flag[@]}" ${doomWad}/freedoom1.wad dump 2 "/tmp/doom-frames-$engine"
      [[ "$example_output" == *"$engine frame time over 2 frames"* ]]
      frames=("/tmp/doom-frames-$engine"/frame_*.ppm)
      [[ ''${#frames[@]} -eq 2 ]]
      for frame in 0 1; do
        read -r actual _ < <(sha256sum "/tmp/doom-frames-$engine/frame_$(printf '%05d' "$frame").ppm")
        if [[ "$actual" != "''${expected[$frame]}" ]]; then
          printf 'Doom %s frame %d: expected %s, got %s\n' \
            "$engine" "$frame" "''${expected[$frame]}" "$actual" >&2
          exit 1
        fi
      done
    done

    # Lua-XDP end to end: a veth pair, the observer on one end, exactly five
    # UDP datagrams from a namespace on the other end, and the test's own port
    # filter so ARP and IPv6 chatter cannot change the count.
    ip link add xdp0 type veth peer name xdp1
    ip netns add peer
    ip link set xdp1 netns peer
    ip addr add 10.99.0.1/24 dev xdp0
    ip link set xdp0 up
    ip -n peer addr add 10.99.0.2/24 dev xdp1
    ip -n peer link set xdp1 up
    timeout 120 ${examples.lua-xdp}/bin/lua-xdp ${../../tests/vm/xdp_count.lua} xdp0 5 \
      >/tmp/xdp-events 2>/tmp/xdp-summary &
    observer=$!
    until grep -q 'observing live traffic' /tmp/xdp-summary; do
      kill -0 "$observer" 2>/dev/null || { cat /tmp/xdp-summary; exit 1; }
      sleep 0.2
    done
    for _ in 1 2 3 4 5; do
      ip netns exec peer bash -c 'echo ping >/dev/udp/10.99.0.1/4242'
    done
    wait "$observer"
    cat /tmp/xdp-events /tmp/xdp-summary
    [[ "$(grep -c 'UDP 4242' /tmp/xdp-events)" -eq 5 ]]
    [[ "$(cat /tmp/xdp-summary)" == *'kernel execution: avg'* ]]

    ${pkgs.lib.optionalString (examples ? python) ''
      # Full CPython and representative built-in/pure-Python modules execute
      # in the kernel; the source image is consumed by its normal importer.
      run_example python 'CPython 3b09041c50e319a2 8.75' - \
        env BPF_CAPSULE_MAX_DRAINS=64 ${examples.python}/bin/python ${../../tests/vm/python.py}
      run_native python ${examples.python}/bin/python ${../../examples/python/benchmark.py}

      # Python-XDP mirrors the Lua check with one isolated interpreter per
      # fiber. Five live packets plus eight test runs on each of two CPUs.
      # Heavy imports run at initialization; simultaneous test packets also
      # exercise a small cold import and shared CPython runtime locks.
      timeout 240 env BPF_CAPSULE_MAX_DRAINS=256 ${examples."python-xdp"}/bin/python-xdp \
        ${../../tests/vm/python_xdp_count.py} xdp0 21 \
        >/tmp/python-xdp-events 2>/tmp/python-xdp-summary &
      observer=$!
      trap 'cat /tmp/python-xdp-events /tmp/python-xdp-summary; kill "$observer" 2>/dev/null || true' EXIT
      until grep -q 'observing live traffic' /tmp/python-xdp-summary; do
        kill -0 "$observer" 2>/dev/null || { cat /tmp/python-xdp-summary; exit 1; }
        sleep 0.2
      done
      for _ in 1 2 3 4 5; do
        ip netns exec peer bash -c 'echo ping >/dev/udp/10.99.0.1/4243'
      done
      program_id=$(bpftool -j net show dev xdp0 | jq -er '.[].xdp[].id')
      printf '\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00\x45\x00\x00\x20\x00\x00\x00\x00\x40\x11\x00\x00\x0a\x63\x00\x02\x0a\x63\x00\x01\x10\x92\x10\x93\x00\x0c\x00\x00test' >/tmp/python-packet
      taskset -c 0 bpftool prog run id "$program_id" data_in /tmp/python-packet repeat 8 &
      sender=$!
      taskset -c 1 bpftool prog run id "$program_id" data_in /tmp/python-packet repeat 8
      wait "$sender"
      wait "$observer"
      trap - EXIT
      cat /tmp/python-xdp-events /tmp/python-xdp-summary
      [[ "$(grep -c '> 4243' /tmp/python-xdp-events)" -eq 21 ]]
      [[ "$(cat /tmp/python-xdp-summary)" == *'kernel execution: avg'* ]]
    ''}
  '';
}
