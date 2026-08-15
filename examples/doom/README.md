# Doom example

This example fetches a pinned revision of PureDOOM, builds it through BPF
Capsule and embeds the generated BPF object in `doom`. Interactive mode
renders adaptive 4:3 truecolor block graphics in an ordinary terminal, so it
also works through SSH; dump mode writes deterministic PPM frames without a
display. The engine is not vendored in this repository.
`PUREDOOM_SOURCE_DIR` can select an existing checkout instead. The build makes
a private copy of its single header, adds a modification/provenance notice,
and applies two documented correctness fixes. `I_InitGraphics` replaces a
previously zeroed framebuffer with `malloc` storage, so the first patch
initializes that replacement too.
The vanilla column drawer can sample up to 127 bytes from a cached texture
post; Freedoom contains a sparse single-patch column which ends earlier, so the
second patch gives cached lumps a zeroed 128-byte guard tail. This removes an
allocator-layout-dependent over-read without adding work to the renderer hot
path. There are no BPF-specific engine changes. The host reports the
in-kernel time for each BPF frame alongside deterministic output.

The WAD is runtime data and is never committed to this repository.
[`tools/fetch-doom-wad.sh`](../../tools/fetch-doom-wad.sh) downloads
[Freedoom](https://freedoom.github.io/) Phase 1 — free content under a
BSD-style license — verified against a pinned SHA-256, and prints its path.
Any DOOM IWAD works the same way: the host stages the file's bytes and the
in-kernel file shim serves them to the engine under the engine's expected
IWAD name, so the file's own name does not matter. Engine start-up (WAD
parsing and the initial level load) runs once behind its own entry, and every
phase — start-up and each frame — completes in a single kernel entry on both
targets. This example never drains continuations: a pending result anywhere
is treated as a hard failure.

```sh
cmake -S . -B build-examples -DCMAKE_BUILD_TYPE=Release \
  -DBPF_CAPSULE_BUILD_EXAMPLES=ON
cmake --build build-examples --target doom -j
sudo build-examples/examples/doom/doom \
  "$(tools/fetch-doom-wad.sh)" tty
mkdir frames
sudo build-examples/examples/doom/doom \
  "$(tools/fetch-doom-wad.sh)" dump 40 frames
```

Dump mode always exports every frame and injects the same two key presses at
frames 6 and 7. The timing summary covers every requested frame; engine
initialization is excluded because it runs through the separate start entry.

## License

This directory is GPL-2.0-only; see [`LICENSE`](LICENSE). It is a separately
licensed example and does not change BPF Capsule's core license.

The engine is derived from
[PureDOOM](https://github.com/Daivuk/PureDOOM), whose port is GPL-2.0, and id
Software's later [GPL-2.0 DOOM source release](https://github.com/id-Software/DOOM).
The pinned repository supplies GPL-2.0 terms, while its single header still
retains id Software's older limited-use notice; this project preserves both
and uses id's later GPL-2.0 engine release together with PureDOOM's GPL
distribution. All private-copy changes, including the dated modification
notice, are kept in [`patches/`](patches/). Installed binaries are accompanied by the
pinned header, these sources, and every patch under
`share/bpf-capsule/examples/doom/source`.

No game data is covered by the source license. Supply a lawfully obtained WAD;
its own terms continue to apply.
