# Csmith differential testing

The installed matrix contains one fixed, terminating Csmith program. It is a
fast regression tripwire, not a representative fuzzing campaign.

Run the larger rotating campaign with:

```sh
nix run .#fuzz
```

The integer profile retains Csmith's normal arrays, pointers, aggregates,
bitfields, packed layouts, volatile objects, division, and safe-math wrappers.
The other profiles add floating point or 128-bit integers. Every case is first
compiled and run natively; programs that do not terminate natively within the
limit are discarded. The remaining program is compiled for Capsule and its
checksum is compared after `bpf_prog_test_run` execution.

Failures retain the generated source, command, metadata, and output below
`$XDG_CACHE_HOME/bpf-capsule/csmith-failures`. A failing program belongs in a
focused regression test after reduction. Run the same command on a Linux 5.15
host or VM with `--target 5.15` for the fixed-map tier.
