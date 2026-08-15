# Lua

Shared support and current language limitations are documented in the
[parent README](../README.md).

This is the small stock-Lua example, shaped like the interpreter it wraps:
the script and batch stdin go into guest-owned buffers, the script runs in
the kernel with one temporary Lua state, and its stdout, error text and exit
code come back the way `lua SCRIPT < input` would return them:

```sh
echo 'print(io.read("a"))' > cat.lua
echo hello | sudo ./lua cat.lua
```

`io.read` supports the `"a"`, `"l"` and `"L"` formats over stdin staged in
full before the run. `--native` runs the same script on the natively built
Lua instead, so the two engines can be compared on any machine. Each run
reports its real execution time on stderr: the kernel's own BPF runtime
accounting (`run_time_ns`) or the native thread's CPU time.

There are no packet APIs, retained VMs, or per-CPU maps here. Those belong to
the separate `lua-xdp` integration.

Lua's native `setjmp`/`longjmp` error mechanism is not yet virtualized. A Lua
throw therefore records its message and exits the Capsule call with code 1,
discarding the temporary VM. Protected recovery (`pcall`, `xpcall`), coroutine
error recovery, and code that relies on catching a Lua error are unsupported;
successful scripts use otherwise unmodified Lua 5.4.8.
