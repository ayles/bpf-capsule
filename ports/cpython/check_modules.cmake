# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Cross builds cannot use CPython's import-based shared-module check. Reject
# missing guest dependencies at configure time, before the expensive BPF link.
file(READ "${BUILD_DIR}/Makefile" configuration)
foreach(
    module
    ZLIB
    _BZ2
    _LZMA
    _ZSTD
    _SQLITE3
    _DECIMAL
    PYEXPAT
    _ELEMENTTREE
    _MD5
    _SHA1
    _SHA2
    _SHA3
    _BLAKE2
    _HMAC
    GRP
    PWD
)
    if(NOT configuration MATCHES "MODULE_${module}_STATE=yes")
        message(FATAL_ERROR "CPython module ${module} was not enabled; inspect ${BUILD_DIR}/config.log")
    endif()
endforeach()
