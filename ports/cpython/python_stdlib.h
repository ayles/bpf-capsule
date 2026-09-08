// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>

// Configure shared library synchronization once, before initializing CPython.
int capsule_python_configure_sqlite(void);

// Install a read-only standard-library image as the first sys.meta_path
// finder. The image remains owned by the embedding for the interpreter's
// lifetime.
int capsule_python_install_stdlib(const void* image, size_t size);
