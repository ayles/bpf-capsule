# QuickJS

This example runs pinned, unmodified QuickJS through Capsule. The host stages
one JavaScript file and all of stdin, the guest exposes `console.log()`,
`readLine()`, and `read()`, and stdout or uncaught-exception text is copied
back after execution:

```sh
echo 'console.log(readLine())' > cat.js
echo hello | sudo ./quickjs cat.js
```

`readLine()` returns the next line without its terminator, or `null` at EOF;
`read()` returns all remaining staged input. Input is batched rather than
streamed. The script buffer is NUL-terminated for `JS_Eval`, but the
terminator is not part of the script length.

`--native` runs the same script with the natively built QuickJS and the same
I/O shims. Each mode reports execution time on stderr: kernel BPF
`run_time_ns` for Capsule or thread CPU time for the native reference.

An uncaught JavaScript exception writes its text to stderr and exits the
Capsule invocation with guest code 1. Framework failures use the negative
codes described by the public Capsule error API.
