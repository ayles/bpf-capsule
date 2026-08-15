// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
#include <stddef.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX 2147483647

void* malloc(unsigned long n);
void* calloc(unsigned long n, unsigned long sz);
void* realloc(void* p, unsigned long n);
void free(void* p);
__attribute__((noreturn)) void abort(void);
__attribute__((noreturn)) void exit(int code);
char* getenv(const char* name);
int system(const char* cmd);
long strtol(const char* s, char** end, int base);
unsigned long strtoul(const char* s, char** end, int base);
unsigned long long strtoull(const char* s, char** end, int base);
double strtod(const char* s, char** end);
int abs(int v);
void qsort(void* base, unsigned long n, unsigned long sz, int (*cmp)(const void*, const void*));

void* bsearch(const void* key, const void* base, unsigned long n, unsigned long sz, int (*cmp)(const void*, const void*));
double atof(const char* s);
int atoi(const char* s);

// alloca is a compiler builtin; -fno-builtin hides it, so name it explicitly.
#define alloca(n) __builtin_alloca(n)
unsigned long malloc_usable_size(void* p);
void* memalign(unsigned long align, unsigned long n);
