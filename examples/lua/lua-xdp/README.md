# Lua on live XDP

Shared support and current language limitations are documented in the
[parent README](../README.md).

This example builds stock Lua 5.4 into a live XDP program. It shares only the
small Lua platform adapter in `../common`; its policy, maps, loader, and packet
API are otherwise self-contained.

The program passes the verifier-owned `struct xdp_md` through the Capsule
boundary. `packet:byte()` and `packet:sub()` read live packet memory. One Lua VM
and compiled policy are retained per active Capsule fiber. Lua sees at most the
first 2,048 bytes of a packet: `#packet` is the visible prefix length, and the
packet methods cannot address bytes beyond that prefix.

Attach the passive observer to the lowest-metric default-route interface:

```sh
sudo nix run .#lua-xdp -- "$PWD/examples/lua/lua-xdp/packet_observer.lua"
```

Run another observer script, optionally on an explicit interface:

```sh
sudo nix run .#lua-xdp -- ./my-observer.lua
sudo nix run .#lua-xdp -- ./my-observer.lua eth0
```

Lua `print()` output and Lua error text are copied to a BPF ring buffer after a
policy invocation finishes. The observer always returns `XDP_PASS`, including
on malformed input or a Capsule error. Its unpinned BPF link detaches
automatically when the host exits, and it never replaces an existing XDP
attachment.

A Lua error terminates that packet's Capsule call and poisons the fiber's VM;
the VM is never reused or traversed for cleanup. Loading a script revision
rebuilds every fiber, replacing poisoned states and closing healthy old states.
The loader publishes the revision only after every VM is ready; a failed reload
blocks packet execution until a later reload succeeds, so fibers never run a
mixture of old and new policies.
Because a poisoned state must be abandoned, repeated error/reload cycles consume
the object's fixed Capsule heap until the BPF object is unloaded. The focused
test below checks the error text and Capsule status, rejects reuse of the
poisoned VM, reloads a valid policy, and checks the 2,048-byte prefix boundary.

The deterministic XDP assertions and steady-state benchmark are separate:

```sh
sudo nix run .#lua-xdp-test -- \
  "$PWD/examples/lua/lua-xdp/packet_filter.lua" \
  "$PWD/examples/lua/lua-xdp/packet_observer.lua"
sudo nix run .#lua-xdp-benchmark -- \
  "$PWD/examples/lua/lua-xdp/packet_filter.lua"
```

Lua state is retained independently by each active Capsule fiber. Scripts
must not treat a Lua global as a process-wide counter shared by all packets.

This is a context-interoperation demonstration, not a production line-rate
observer. Its multi-megabyte per-fiber VM state makes both hot throughput and
cold-cache latency hardware-dependent, and polling it on a busy link can
throttle traffic visibly. Run the benchmark before and after changes on the
same host, and measure again on the deployment machine before using the pattern
outside a demo.
