// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// There are no files here, so FILE is opaque and every call fails cleanly.
// A program that really needs output goes through its own driver instead
// (Lua's print, for instance, is redirected at the luaconf.h level).
#pragma once
#include <stddef.h>
#include <stdarg.h>

typedef struct _FILE FILE;

#define EOF (-1)
#define BUFSIZ 8192
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define L_tmpnam 32
#define FILENAME_MAX 260
#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2

extern FILE* stdin;
extern FILE* stdout;
extern FILE* stderr;

FILE* fopen(const char* path, const char* mode);
FILE* freopen(const char* path, const char* mode, FILE* f);
FILE* tmpfile(void);
int fclose(FILE* f);
int fflush(FILE* f);
unsigned long fread(void* p, unsigned long sz, unsigned long n, FILE* f);
unsigned long fwrite(const void* p, unsigned long sz, unsigned long n, FILE* f);
int fprintf(FILE* f, const char* fmt, ...);
int printf(const char* fmt, ...);
int snprintf(char* s, unsigned long n, const char* fmt, ...);
int sprintf(char* s, const char* fmt, ...);
int vsnprintf(char* s, unsigned long n, const char* fmt, va_list ap);
int fputs(const char* s, FILE* f);
int fputc(int c, FILE* f);
int putc(int c, FILE* f);
char* fgets(char* s, int n, FILE* f);
int getc(FILE* f);
int ungetc(int c, FILE* f);
int ferror(FILE* f);
int feof(FILE* f);
void clearerr(FILE* f);
int setvbuf(FILE* f, char* buf, int mode, unsigned long sz);
int fseek(FILE* f, long off, int whence);
long ftell(FILE* f);
int remove(const char* path);
int rename(const char* a, const char* b);
char* tmpnam(char* s);
int sscanf(const char* s, const char* fmt, ...);
