// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Freestanding libc for programs compiled into the kernel. These headers
// shadow the host's: the host set describes a machine with an operating
// system under it, and this one does not have that. Definitions live in
// src/libc/freestanding.c.
#pragma once
#include <stddef.h>

void* memcpy(void* d, const void* s, unsigned long n);
void* memmove(void* d, const void* s, unsigned long n);
void* memset(void* d, int c, unsigned long n);
int memcmp(const void* a, const void* b, unsigned long n);
void* memchr(const void* s, int c, unsigned long n);
unsigned long strlen(const char* s);
unsigned long strnlen(const char* s, unsigned long max);
int strcmp(const char* a, const char* b);
int strncmp(const char* a, const char* b, unsigned long n);
int strcoll(const char* a, const char* b);
char* strcpy(char* d, const char* s);
char* strncpy(char* d, const char* s, unsigned long n);
char* strcat(char* d, const char* s);
char* strchr(const char* s, int c);
char* strrchr(const char* s, int c);
unsigned long strspn(const char* s, const char* accept);
unsigned long strcspn(const char* s, const char* reject);
char* strpbrk(const char* s, const char* accept);
char* strstr(const char* h, const char* n);
char* strerror(int e);
