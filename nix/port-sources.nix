# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Offline sources for the CMake ports. Shared by examples, tests and benchmarks.
{ fetchzip }:
{
  zlib = fetchzip {
    url = "https://github.com/madler/zlib/archive/da607da739fa6047df13e66a2af6b8bec7c2a498.tar.gz";
    hash = "sha256-Sthd9RsydSLaITNlBp6g1X35WKZdS4h7gr0QhRqdGoI=";
  };
  sqlite = fetchzip {
    url = "https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip";
    hash = "sha256-ij7Yw6LuWXeetH3Zs6ir+4HdQTpynPlSIMspl0nTuUI=";
  };
  lua = fetchzip {
    url = "https://www.lua.org/ftp/lua-5.5.1.tar.gz";
    hash = "sha256-vb3Nt5dMPL/G6L1MmJPGQnQT3F8p6iK6Gu2F/cG00ho=";
  };
  wasm3 = fetchzip {
    url = "https://github.com/wasm3/wasm3/archive/0cd38327f0c721e75172f4f1eeb55854dc0517af.tar.gz";
    hash = "sha256-0LFsyAhT51rhXORnxMQ8/Jt22F6neE5aZZSxF5c7HBw=";
  };
  llama2 = fetchzip {
    url = "https://github.com/karpathy/llama2.c/archive/350e04fe35433e6d2941dce5a1f53308f87058eb.tar.gz";
    hash = "sha256-pFYN2JnKl/fgofqZvwG42YUkXqDrzTo4PjWbHhDvml8=";
  };
  quickjs = fetchzip {
    url = "https://github.com/bellard/quickjs/archive/04be246001599f5995fa2f2d8c91a0f198d3f34c.tar.gz";
    hash = "sha256-IGq2a2MQtp45hrPL/1CyF87vS8hfMbtKK1NVN6+n+Tk=";
  };
  puredoom = fetchzip {
    url = "https://github.com/Daivuk/PureDOOM/archive/355cfbd16fac119718879239336ee2ea408886bd.tar.gz";
    hash = "sha256-wW3psXtWuyxByUlelkTFp3BwWjp5W+uUaHeUEqr+sWw=";
  };
  cpython = fetchzip {
    url = "https://github.com/python/cpython/archive/refs/tags/v3.14.7.tar.gz";
    hash = "sha256-NaLBOxFZv3zljyREKrDUw7UBx3iUabNybAZHhc+CgJc=";
  };
  bzip2 = fetchzip {
    url = "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz";
    hash = "sha256-Uvi4JZPPERK3gym4yoaeTEJwKXF5brBAEN7GgF+iF6g=";
  };
  xz = fetchzip {
    url = "https://github.com/tukaani-project/xz/releases/download/v5.8.3/xz-5.8.3.tar.xz";
    hash = "sha256-DhBCivleFs6+2f57v5IkqRmMPGHaG+VZOg3ZiRIxIXM=";
  };
  zstd = fetchzip {
    url = "https://github.com/facebook/zstd/archive/v1.5.7.tar.gz";
    hash = "sha256-tNFWIT9ydfozB8dWcmTMuZLCQmQudTFJIkSr0aG7S44=";
  };
}
