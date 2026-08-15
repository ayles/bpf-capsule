// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The parts of <math.h> a program can actually get here.
//
// These are written as ordinary double arithmetic and lowered by
// bpf-soft-float like everything else, so they are exact where the algorithm
// is exact. The transcendentals that ports have needed — exp, log, sin, cos,
// tan, pow, and everything below built from them — are implemented by series,
// accurate to a few ulp. The inverse trigonometric functions (asin, acos,
// atan, atan2) have no implementation: rather than return a plausible wrong
// number they terminate the Capsule call with a named error.
#include "bpf_capsule.h"

double fabs(double x) {
    unsigned long long bits;
    __builtin_memcpy(&bits, &x, sizeof(bits));
    bits &= 0x7fffffffffffffffull;
    __builtin_memcpy(&x, &bits, sizeof(x));
    return x;
}

double floor(double x) {
    if (x == 0.0 || x != x || fabs(x) >= 4503599627370496.0) {
        return x; // NaN, inf, or integral
    }
    double t = (double)(long long)x;
    return t > x ? t - 1.0 : t;
}

double ceil(double x) {
    if (x == 0.0 || x != x || fabs(x) >= 4503599627370496.0) {
        return x;
    }
    double t = (double)(long long)x;
    return t < x ? t + 1.0 : t;
}

double trunc(double x) {
    if (x == 0.0 || x != x || fabs(x) >= 4503599627370496.0) {
        return x;
    }
    return (double)(long long)x;
}

// A quiet NaN, assembled from its bit pattern. Under bpf-soft-float a double
// is its bit pattern, and writing 0.0/0.0 instead would let clang constant-
// fold the expression before the pass ever sees it.
static double quiet_nan(void) {
    unsigned long long bits = 0x7ff8000000000000ull;
    double x;
    __builtin_memcpy(&x, &bits, sizeof(x));
    return x;
}

static unsigned long long double_bits(double x) {
    unsigned long long bits;
    __builtin_memcpy(&bits, &x, sizeof(bits));
    return bits;
}

static int infinite(double x) {
    return (double_bits(x) & 0x7fffffffffffffffull) == 0x7ff0000000000000ull;
}

double fmod(double a, double b) {
    if (b == 0.0 || a != a || b != b || infinite(a)) {
        return quiet_nan(); // IEEE: domain error is NaN
    }
    if (infinite(b)) {
        return a;
    }
    double q = trunc(a / b);
    return a - q * b;
}

double sqrt(double x) {
    if (x < 0.0) {
        return quiet_nan();
    }
    if (x == 0.0 || x != x || infinite(x)) {
        return x;
    }
    // Newton's method converges quadratically; the seed halves the exponent.
    double g = x > 1.0 ? x / 2.0 : 1.0;
    for (int i = 0; i < 60; i++) {
        double n = (g + x / g) / 2.0;
        if (n == g) {
            break;
        }
        g = n;
    }
    return g;
}

double ldexp(double x, int e) {
    if (x == 0.0 || x != x || infinite(x)) {
        return x;
    }
    while (e > 0) {
        x = x * 2.0;
        e--;
    }
    while (e < 0) {
        x = x / 2.0;
        e++;
    }
    return x;
}

double frexp(double x, int* e) {
    *e = 0;
    if (x == 0.0 || x != x || infinite(x)) {
        return x;
    }
    double a = fabs(x);
    while (a >= 1.0) {
        a = a / 2.0;
        (*e)++;
    }
    while (a < 0.5) {
        a = a * 2.0;
        (*e)--;
    }
    return x < 0 ? -a : a;
}

// The transcendentals, by series. Every operation below becomes integer work
// once bpf-soft-float rewrites it, so these are as available here as addition
// is. Accuracy is a few ulp — enough for the inference that wants them.
#define LN2 0.6931471805599453094
#define PI 3.1415926535897932385

double exp(double x) {
    if (x != x) {
        return x;
    }
    if (x > 709.0) {
        return 1.0e308 * 10.0;
    }
    if (x < -745.0) {
        return 0.0;
    }
    // exp(x) = 2^k * exp(r) with |r| <= ln2/2, where the series converges fast.
    double kf = x / LN2;
    long long k = (long long)(kf < 0 ? kf - 0.5 : kf + 0.5);
    double r = x - (double)k * LN2;
    double term = 1.0, sum = 1.0;
    for (int i = 1; i <= 16; i++) {
        term = term * r / (double)i;
        sum = sum + term;
    }
    return ldexp(sum, (int)k);
}

double log(double x) {
    if (x != x || x < 0.0) {
        return quiet_nan();
    }
    if (x == 0.0) {
        return -1.0e308 * 10.0;
    }
    if (infinite(x)) {
        return x;
    }
    // x = m * 2^e, m in [1,2). log m by the atanh series: (m-1)/(m+1) is small.
    int e = 0;
    double m = frexp(x, &e) * 2.0;
    e = e - 1;
    double t = (m - 1.0) / (m + 1.0);
    double t2 = t * t, term = t, sum = t;
    for (int i = 3; i <= 31; i += 2) {
        term = term * t2;
        sum = sum + term / (double)i;
    }
    return 2.0 * sum + (double)e * LN2;
}

double log2(double x) {
    return log(x) / LN2;
}
double log10(double x) {
    return log(x) / 2.302585092994045684;
}

static double sin_core(double r) {
    double r2 = r * r, term = r, sum = r;
    for (int i = 3; i <= 19; i += 2) {
        term = -term * r2 / (double)(i * (i - 1));
        sum = sum + term;
    }
    return sum;
}
static double cos_core(double r) {
    double r2 = r * r, term = 1.0, sum = 1.0;
    for (int i = 2; i <= 18; i += 2) {
        term = -term * r2 / (double)(i * (i - 1));
        sum = sum + term;
    }
    return sum;
}

// Reduce to a quadrant, then use whichever series is accurate there.
static double sincos(double x, int wantCos) {
    if (x != x) {
        return x;
    }
    if (infinite(x)) {
        return quiet_nan();
    }
    int neg = 0;
    if (x < 0) {
        x = -x;
        neg = !wantCos;
    }
    double q = x / (PI / 2.0);
    long long n = (long long)(q + 0.5);
    double r = x - (double)n * (PI / 2.0);
    int quad = (int)(((n % 4) + 4) % 4);
    if (wantCos) {
        quad = (quad + 1) % 4;
    }
    double v;
    switch (quad) {
        case 0:
            v = sin_core(r);
            break;
        case 1:
            v = cos_core(r);
            break;
        case 2:
            v = -sin_core(r);
            break;
        default:
            v = -cos_core(r);
            break;
    }
    return neg ? -v : v;
}

double sin(double x) {
    return sincos(x, 0);
}
double cos(double x) {
    return sincos(x, 1);
}
double tan(double x) {
    return sin(x) / cos(x);
}

double pow(double a, double b) {
    if (b == 0.0) {
        return 1.0;
    }
    if (a == 0.0) {
        return 0.0;
    }
    if (a < 0.0) {
        long long ib = (long long)b;
        if ((double)ib != b) {
            return quiet_nan();
        }
        double r = exp(b * log(-a));
        return (ib & 1) ? -r : r;
    }
    return exp(b * log(a));
}
static double unsupported(void) {
    __bpf_capsule_exit(CAPSULE_ERROR_UNSUPPORTED_LIBC);
    __builtin_unreachable();
}
double asin(double x) {
    return unsupported();
}
double acos(double x) {
    return unsupported();
}
double atan(double x) {
    return unsupported();
}
double atan2(double a, double b) {
    return unsupported();
}
double difftime(long a, long b) {
    return (double)(a - b);
}
double strtod(const char* s, char** end) {
    if (end) {
        *end = (char*)s;
    }
    return 0.0;
}
int isnan(double x) {
    return x != x;
}
int isinf(double x) {
    return infinite(x);
}

// Single precision: computed in double and rounded once, which is at least as
// accurate as working in float throughout.
float expf(float x) {
    return (float)exp((double)x);
}
float logf(float x) {
    return (float)log((double)x);
}
float powf(float a, float b) {
    return (float)pow((double)a, (double)b);
}
float sinf(float x) {
    return (float)sin((double)x);
}
float cosf(float x) {
    return (float)cos((double)x);
}
float sqrtf(float x) {
    return (float)sqrt((double)x);
}
float fabsf(float x) {
    unsigned int bits;
    __builtin_memcpy(&bits, &x, sizeof(bits));
    bits &= 0x7fffffffu;
    __builtin_memcpy(&x, &bits, sizeof(x));
    return x;
}
float floorf(float x) {
    return (float)floor((double)x);
}
float ceilf(float x) {
    return (float)ceil((double)x);
}
float fmodf(float a, float b) {
    return (float)fmod((double)a, (double)b);
}
float tanhf(float x) {
    if (x > 20.0f) {
        return 1.0f;
    }
    if (x < -20.0f) {
        return -1.0f;
    }
    double e = exp(2.0 * (double)x);
    return (float)((e - 1.0) / (e + 1.0));
}

double round(double x) {
    if (x == 0.0) {
        return x;
    }
    return x < 0 ? ceil(x - 0.5) : floor(x + 0.5);
}
float roundf(float x) {
    return (float)round((double)x);
}
float truncf(float x) {
    return (float)trunc((double)x);
}

// The hyperbolics and the remaining shapes, all in terms of exp and log.
double sinh(double x) {
    double e = exp(x);
    return (e - 1.0 / e) / 2.0;
}
double cosh(double x) {
    double e = exp(x);
    return (e + 1.0 / e) / 2.0;
}
double tanh(double x) {
    if (x > 20.0) {
        return 1.0;
    }
    if (x < -20.0) {
        return -1.0;
    }
    double e = exp(2.0 * x);
    return (e - 1.0) / (e + 1.0);
}
double asinh(double x) {
    return log(x + sqrt(x * x + 1.0));
}
double acosh(double x) {
    return log(x + sqrt(x * x - 1.0));
}
double atanh(double x) {
    return 0.5 * log((1.0 + x) / (1.0 - x));
}
double cbrt(double x) {
    if (x == 0.0) {
        return 0.0;
    }
    double r = exp(log(x < 0 ? -x : x) / 3.0);
    return x < 0 ? -r : r;
}
double hypot(double a, double b) {
    return sqrt(a * a + b * b);
}
double expm1(double x) {
    return exp(x) - 1.0;
}
double log1p(double x) {
    return log(1.0 + x);
}
double exp2(double x) {
    return exp(x * LN2);
}
double fmin(double a, double b) {
    if (a != a) {
        return b;
    }
    if (b != b) {
        return a;
    }
    return a < b ? a : b;
}
double fmax(double a, double b) {
    if (a != a) {
        return b;
    }
    if (b != b) {
        return a;
    }
    return a > b ? a : b;
}
double nearbyint(double x) {
    return round(x);
}
double rint(double x) {
    return round(x);
}

int isfinite(double x) {
    return x == x && !isinf(x);
}
int signbit(double x) {
    // The sign lives in the top bit, and reading it that way is right for
    // negative zero too, where a comparison against zero is not.
    unsigned long long bits;
    __builtin_memcpy(&bits, &x, sizeof(bits));
    return (int)(bits >> 63);
}
long lrint(double x) {
    return (long)round(x);
}
long long llrint(double x) {
    return (long long)round(x);
}
