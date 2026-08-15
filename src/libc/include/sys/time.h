// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Provided so the host's version — which drags in the C library's own
// struct definitions — never gets picked up.
#pragma once
#include <time.h>
struct timeval {
    long tv_sec;
    long tv_usec;
};
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};
int gettimeofday(struct timeval* tv, struct timezone* tz);
