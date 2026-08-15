// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
typedef long time_t;
typedef long clock_t;
#define CLOCKS_PER_SEC 1000000
struct tm {
    int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst;
    long tm_gmtoff;
    const char* tm_zone;
};
time_t time(time_t* t);
clock_t clock(void);
struct tm* localtime(const time_t* t);
struct tm* gmtime(const time_t* t);
time_t mktime(struct tm* tm);
double difftime(time_t a, time_t b);
unsigned long strftime(char* s, unsigned long max, const char* fmt, const struct tm* tm);

// No clock without an operating system: the declaration exists so programs
// compile, and the call reports ENOSYS.
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
struct timespec {
    long tv_sec;
    long tv_nsec;
};
int clock_gettime(int clk, struct timespec* ts);
struct timeval;
struct tm* localtime_r(const time_t* t, struct tm* out);
