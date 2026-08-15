// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
#define SIGINT 2
typedef void (*sighandler_t)(int);
#define SIG_ERR ((sighandler_t) - 1)
sighandler_t signal(int sig, sighandler_t h);
int raise(int sig);
typedef volatile int sig_atomic_t;
