# Lua examples

Both examples compile unmodified Lua 5.4.8 sources with the small platform
adapter in `common/`:

- `lua/` is a one-shot script/stdout example with one temporary VM;
- `lua-xdp/` retains one policy VM per active Capsule fiber and reads packets
  directly from the borrowed XDP context.

## Current language limitations

Capsule does not yet virtualize native stack unwinding. Lua's normal
`setjmp`/`longjmp` implementation is therefore replaced with a terminating
Capsule error path: the Lua message is recorded, the complete managed call is
aborted, and that partially mutated VM cannot be reused.

Consequently, these Lua features are not supported yet:

- recovering from an error with `pcall` or `xpcall`;
- coroutine paths that throw or recover across a protected Lua boundary;
- user code that deliberately raises and catches errors;
- native modules that rely on `setjmp`/`longjmp` or C++ exceptions;
- operating-system functionality such as files, processes, dynamic modules,
  sockets, and environment mutation from managed code.

Normal parsing, bytecode execution, garbage collection, tables, strings,
integer and software-floating-point arithmetic, and C functions that return
normally are supported. Managed unwinding is tracked as future work because
the same mechanism should support both Lua protected errors and C++ exception
cleanup rather than introducing a Lua-only substitute.
