# Csmith differential test

The release matrix generates one fixed, terminating Csmith program and runs
the same translation unit natively and through Capsule. Its checksum is a
quick tripwire for arrays, pointers, aggregates, bitfields, packed layouts,
volatile objects, division, and Csmith's safe-math helpers. It is not a fuzzing
campaign.

Configure a case explicitly with:

```sh
cmake -S . -B build \
  -DBPF_CAPSULE_CSMITH_CASE=/path/to/case.c \
  -DBPF_CAPSULE_CSMITH_INCLUDE_DIR=/path/to/csmith/include
```

Generated failures should be reduced into focused compiler or runtime tests.

For a rotating integer, floating-point, and 128-bit campaign, run:

```sh
nix develop -c python3 tests/csmith/fuzz.py --count 30 --target 6.9
```

The driver stores the source, command metadata, and combined log for every
failure under `$XDG_CACHE_HOME/bpf-capsule/csmith-failures`. It uses this same
GTest fixture; there is no second checksum implementation or build pipeline.
