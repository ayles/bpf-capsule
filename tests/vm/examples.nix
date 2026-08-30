# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{
  pkgs,
  examples,
  kernelPackages,
  targetKernel,
  llamaFixtures,
  doomWad,
  arena ? false,
}:
pkgs.testers.runNixOSTest {
  name = "bpf-capsule-examples-${builtins.replaceStrings [ "." ] [ "" ] targetKernel}";

  nodes.machine =
    { lib, pkgs, ... }:
    {
      boot.kernelPackages = kernelPackages;
      virtualisation = {
        memorySize = 6144;
        cores = 6;
        graphics = false;
      };
      environment.systemPackages = with pkgs; [
        bpftools
        libbpf
      ];
      system.stateVersion = "23.11";
    }
    // lib.optionalAttrs arena {
      hardware.deviceTree.enable = false;
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    print(machine.succeed("uname -a"))

    root = "${examples}/libexec/bpf-capsule/examples"

    def run_example(name, command, marker):
        output = machine.succeed(
            "ulimit -l unlimited; " + command + " 2>&1"
        )
        print("RUN:" + name)
        print(output)
        assert marker in output, name + " did not print " + repr(marker)

    run_example("fib", root + "/fib/fib", "fib(20) = 6765")
    run_example("zlib", root + "/zlib/zlib 65536", "continuation drains:")
    run_example("sqlite", root + "/sqlite/sqlite", "rows=11 checksum=4e4d372ad01ecc09")
    run_example("wasm3", root + "/wasm3/wasm3 4096", "stock zlib Wasm: 4096 ->")
    run_example("lua", root + "/lua/lua " + root + "/lua/script.lua", "Lua checksum\t16898\ttrue\t0")
    run_example("quickjs", root + "/quickjs/quickjs " + root + "/quickjs/script.js", "checksum 807746 text-bytes 743 matches 100")
    run_example("rust", root + "/rust/rust", "Rust panic: status=exited code=101")
    run_example("llama2", root + "/llama2/llama2 ${llamaFixtures}/llama2-tiny.bin 4", "tokens: 15 15 15 15")
    run_example("llama2-q8", root + "/llama2/llama2q ${llamaFixtures}/llama2q-tiny.bin 4", "tokens: 15 15 15 15")

    machine.succeed("mkdir -p /tmp/doom-frames")
    run_example(
        "doom",
        root + "/doom/doom ${doomWad}/freedoom1.wad dump 2 /tmp/doom-frames",
        "dump done: status=0",
    )
    machine.succeed("test $(find /tmp/doom-frames -name 'frame_*.ppm' | wc -l) -eq 2")
    doom_frame_sha256 = [
        "a95d4cb55feeb7b3ef7c2bd289f32d1ce3105da4e91d71348eb1eaa6dc9adce2",
        "06553576c3d898219971710fce745457db31cfd76ae28d6c10ad72804d37d881",
    ]
    actual_doom_frame_sha256 = [
        machine.succeed(f"sha256sum /tmp/doom-frames/frame_{frame:05d}.ppm").split()[0]
        for frame in range(len(doom_frame_sha256))
    ]
    assert actual_doom_frame_sha256 == doom_frame_sha256, (
        f"Doom frame hashes: expected {doom_frame_sha256}, got {actual_doom_frame_sha256}"
    )
    machine.shutdown()
  '';
}
