# Third-party code and data

BPF Capsule's compiler and runtime are Apache-2.0 with the LLVM exception. The
proof programs fetch most library sources at configure time; those checkouts
are not committed to this repository and keep their upstream licenses.

| Example | Pinned source | License | In this repository |
| --- | --- | --- | --- |
| zlib | `e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca` | zlib | Generated Wasm fixture only |
| Lua | 5.4.8 tarball, SHA-256 `4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae` | MIT | No upstream source |
| QuickJS | `04be246001599f5995fa2f2d8c91a0f198d3f34c` | MIT | No upstream source |
| SQLite | 3.45.1 amalgamation, SHA-256 `5592243caf28b2cdef41e6ab58d25d653dfc53deded8450eb66072c929f030c4` | Public domain | No upstream source |
| wasm3 | `6b8bcb1e07bf26ebef09a7211b0a37a446eafd52` (v0.5.0) | MIT | No upstream source |
| llama2.c | `350e04fe35433e6d2941dce5a1f53308f87058eb` | MIT | No upstream source or model |
| Doom/PureDOOM | `355cfbd16fac119718879239336ee2ea408886bd` | GPL-2.0-only distribution; legacy notice retained in the header | Integration, modification notice, and two correctness patches |
| Rust `core` and `alloc` | selected `rustc` sysroot (1.97.1 in the pinned Nix build) | Apache-2.0 OR MIT | only needed bitcode is linked into the Rust examples |
| Rust `compiler_builtins` | selected `rustc` sysroot | MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0) | only needed bitcode is linked into the Rust examples |
| Csmith runtime | selected nixpkgs Csmith package | BSD-2-Clause | optional generated differential-test object |

The pins and download URLs in the example `CMakeLists.txt` files and
`package.nix` are kept identical. The `.#examples` Nix output fetches them as
hash-pinned derivations and supplies their source directories to CMake, so
CMake performs no downloads. A direct CMake caller can supply each
`*_BPF_SOURCE_DIR` cache variable (`PUREDOOM_SOURCE_DIR` for Doom) instead.

## Material retained in-tree

`src/libc/tlsf.c` and `tlsf.h` are an adapted TLSF allocator by
Matthew Conte, distributed under the BSD 3-Clause license. The complete
copyright notice and license are retained at the top of `tlsf.h` and in
`src/libc/TLSF-LICENSE` for installed binary bundles.

`examples/wasm3/zlib_wasm_module.h` is a generated Wasm binary containing the
project's freestanding guest shim and zlib inflate code. The zlib portion is
distributed under this notice:

> Copyright notice:
>
> (C) 1995-2026 Jean-loup Gailly and Mark Adler
>
> This software is provided 'as-is', without any express or implied
> warranty. In no event will the authors be held liable for any damages
> arising from the use of this software.
>
> Permission is granted to anyone to use this software for any purpose,
> including commercial applications, and to alter it and redistribute it
> freely, subject to the following restrictions:
>
> 1. The origin of this software must not be misrepresented; you must not
> claim that you wrote the original software. If you use this software in a
> product, an acknowledgment in the product documentation would be appreciated
> but is not required.
> 2. Altered source versions must be plainly marked as such, and must not be
> misrepresented as being the original software.
> 3. This notice may not be removed or altered from any source distribution.
>
> Jean-loup Gailly — jloup@gzip.org
> Mark Adler — madler@alumni.caltech.edu

The generated header therefore uses the composite SPDX expression
`Zlib AND Apache-2.0 WITH LLVM-exception`: zlib covers the compiled inflate
sources and the project license covers the guest shim and generated container.

`examples/doom` is GPL-2.0-only and contains its own `LICENSE` and provenance
note. PureDOOM is fetched at the pinned revision rather than vendored. That
revision's repository includes the GPL-2.0 license text added by the PureDOOM
author, while `PureDOOM.h` still retains id Software's older limited-use
notice. This project preserves both notices and relies on the repository's GPL
distribution of the port together with id Software's later GPL-2.0 release of
the engine source. The build applies the files in `examples/doom/patches/` to a
private copy of the single header. The first adds a dated modification and
provenance notice. The next zeroes the replacement buffer after
`I_InitGraphics` replaces the already-zeroed `V_Init` framebuffer with
uninitialized `malloc` storage. The final patch gives cached WAD lumps a
zeroed 128-byte guard tail for the vanilla column drawer's masked `0..127`
source index; sparse single-patch
columns can otherwise read neighboring allocator data. These are
allocator-independent output-correctness fixes, not BPF adaptations. id
Software officially re-released the engine source under GPL-2.0, and PureDOOM
distributed the port with the GPL-2.0 text. The fetched source retains its
upstream notices and the alterations are represented explicitly by the GPL
example's patch files. The installed Doom bundle includes the original pinned
header, project source, build file, and every patch under
`share/bpf-capsule/examples/doom/source`, providing the corresponding source
needed to rebuild the distributed executable.

`src/runtime/host/bpf_capsule_host.h` is project-authored and dual-licensed as
Apache-2.0 with the LLVM exception or GPL-2.0-only so the GPL Doom host can use
the same error-checked loader helpers as the permissive examples.

When examples are enabled, the CMake install step places the fetched zlib,
Lua, wasm3, llama2.c, and QuickJS license files plus the in-tree TLSF notice
under `share/licenses/bpf-capsule-examples`; Doom installs its GPL license in a
separate directory. The Nix example package uses that same CMake install path.
SQLite's upstream amalgamation is dedicated to the public domain. Rust target
libraries are consumed from the selected toolchain: `core` and `alloc` are
Apache-2.0 OR MIT, while `compiler_builtins` uses the composite expression in
the table above. Its verbatim upstream notice, including the MIT text, Apache
2.0 text, LLVM exception, and compiler-rt attribution, is installed as
`share/licenses/bpf-capsule/compiler-builtins-LICENSE.txt`. The non-published
`bpf-capsule-rt` Cargo package records the project SPDX expression and is
installed under the project prefix beside the main project license rather than
carrying a redundant crate-local license copy.

The optional Csmith differential case incorporates Csmith's generated runtime
from `csmith.h`. Its host/object and the verbatim `CSMITH-LICENSE` are installed
only when `BPF_CAPSULE_INSTALL_TEST_ARTIFACTS` is enabled.

## Build and link dependencies

The compiler plugin links to LLVM 22, licensed Apache-2.0 WITH LLVM-exception.
Example hosts dynamically link libbpf, available under LGPL-2.1-only OR
BSD-2-Clause. These dependencies are not copied into this source tree; a binary
distributor must follow the terms of the concrete libraries it ships.

## Runtime data

No WAD, model, or checkpoint data is committed to this repository.
`tools/generate-llama-fixtures.py` creates small project-authored numerical
fixtures at test time; they contain no upstream model parameters.

`tools/fetch-doom-wad.sh` optionally downloads
[Freedoom](https://freedoom.github.io/) Phase 1 (`freedoom1.wad`) for the
Doom example and the benchmark matrix, pinned at release 0.13.0 with SHA-256
verification of both the archive
(`3f9b264f3e3ce503b4fb7f6bdcb1f419d93c7b546f4df3e874dd878db9688f59`) and the
extracted WAD
(`7323bcc168c5a45ff10749b339960e98314740a734c30d4b9f3337001f9e703d`).
Freedoom is free content under a BSD-style license; its license text ships
inside the downloaded archive. The WAD is cached locally and never enters
this repository. Users may substitute any lawfully obtained DOOM IWAD and
remain responsible for its applicable terms. llama2 model checkpoints are
never downloaded; their paths are supplied by the user.
