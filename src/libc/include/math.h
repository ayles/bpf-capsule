// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Floating point does not exist on BPF; the bpf-soft-float pass rewrites
// every floating-point operation into the integer routines in softfloat.c.
// These declarations bind to the compact range-reduced implementations in
// mathfns.c; they are not a correctly-rounded general-purpose libm.
#pragma once
#define HUGE_VAL (__builtin_huge_val())
#define HUGE_VALF (__builtin_huge_valf())
#define INFINITY (__builtin_inff())
#define NAN (__builtin_nanf(""))
double floor(double x);
double ceil(double x);
double fmod(double a, double b);
double pow(double a, double b);
double sqrt(double x);
double exp(double x);
double log(double x);
double log2(double x);
double log10(double x);
double sin(double x);
double cos(double x);
double tan(double x);
double asin(double x);
double acos(double x);
double atan(double x);
double atan2(double a, double b);
double frexp(double x, int* e);
double ldexp(double x, int e);
double fabs(double x);
double copysign(double x, double y);
double fma(double a, double b, double c);
int isnan(double x);
int isinf(double x);

// The single-precision entry points. Without these declarations a caller
// gets an implicit one, which promotes its float argument to double and
// returns int — a silently mismatched call that only shows up much later.
float expf(float x);
float logf(float x);
float powf(float a, float b);
float sinf(float x);
float cosf(float x);
float sqrtf(float x);
float fabsf(float x);
float copysignf(float x, float y);
float fmaf(float a, float b, float c);
float floorf(float x);
float ceilf(float x);
float fmodf(float a, float b);
float tanhf(float x);
double round(double x);
float roundf(float x);
double trunc(double x);
float truncf(float x);
double sinh(double x);
double cosh(double x);
double tanh(double x);
double asinh(double x);
double acosh(double x);
double atanh(double x);
double cbrt(double x);
double hypot(double a, double b);
double expm1(double x);
double log1p(double x);
double exp2(double x);
double fmin(double a, double b);
double fmax(double a, double b);
double nearbyint(double x);
double rint(double x);
int isfinite(double x);
int signbit(double x);
long lrint(double x);
long long llrint(double x);
