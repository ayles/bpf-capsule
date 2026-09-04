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
      example_output="$("$@" 2>&1)"
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

    run_example fib 'fib(20) = 6765' - ${examples.fib}/bin/fib
    run_example zlib 'stock zlib:' 0 ${examples.zlib}/bin/zlib 65536
    run_example sqlite 'rows=12 checksum=693506f4cc70de84' 0 ${examples.sqlite}/bin/sqlite
    run_example wasm3 'stock zlib Wasm: 4096 ->' 0 ${examples.wasm3}/bin/wasm3 4096
    run_example lua $'Lua checksum\t16898\ttrue\t0\ttrue' 0 \
      ${examples.lua}/bin/lua ${../../examples/lua/script.lua}
    run_example quickjs 'checksum 807746 text-bytes 743 matches 100' 0 \
      ${examples.quickjs}/bin/quickjs ${../../examples/quickjs/script.js}
    run_example rust 'Rust panic: status=exited code=101' 0 ${examples.rust}/bin/rust

    story='text: Once upon a time, there was a little girl named Lily. She loved to play outside in the park.'
    run_example llama2 "$story" 15 env BPF_CAPSULE_MAX_DRAINS=15 \
      ${examples.llama2}/bin/llama2 ${llamaModel} 32 ${llamaTokenizer}
    [[ "$example_output" == *'native reference: match'* ]]
    run_example llama2-q8 "$story" 10 env BPF_CAPSULE_MAX_DRAINS=10 \
      ${examples.llama2}/bin/llama2-q8 ${llamaQ8Model} 32 ${llamaTokenizer}
    [[ "$example_output" == *'native reference: match'* ]]

    mkdir -p /tmp/doom-frames
    run_example doom 'dump done: status=0' - \
      ${examples.doom}/bin/doom ${doomWad}/freedoom1.wad dump 2 /tmp/doom-frames
    frames=(/tmp/doom-frames/frame_*.ppm)
    [[ ''${#frames[@]} -eq 2 ]]
    expected=(
      a95d4cb55feeb7b3ef7c2bd289f32d1ce3105da4e91d71348eb1eaa6dc9adce2
      06553576c3d898219971710fce745457db31cfd76ae28d6c10ad72804d37d881
    )
    for frame in 0 1; do
      read -r actual _ < <(sha256sum "/tmp/doom-frames/frame_$(printf '%05d' "$frame").ppm")
      if [[ "$actual" != "''${expected[$frame]}" ]]; then
        printf 'Doom frame %d: expected %s, got %s\n' \
          "$frame" "''${expected[$frame]}" "$actual" >&2
        exit 1
      fi
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
  '';
}
