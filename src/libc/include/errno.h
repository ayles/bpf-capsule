// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
int* __bpf_capsule_errno_location(void);
#define errno (*__bpf_capsule_errno_location())
#define EDOM 33
#define ERANGE 34
#define EINTR 4
#define ENOENT 2
#define EBADF 9
#define ENOMEM 12
#define ENOSYS 38
#define EINVAL 22
#define EOVERFLOW 75
