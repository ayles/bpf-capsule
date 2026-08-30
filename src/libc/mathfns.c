// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The parts of <math.h> a program can actually get here.
//
// These are written as ordinary double arithmetic and lowered by
// bpf-soft-float like everything else. Basic operations and IEEE special
// cases are explicit; the transcendental family uses compact range-reduced
// series intended for inference workloads, not a correctly-rounded libm. A
// math function this file does not define fails at build time at its call
// site, never as a runtime surprise.
#include "bpf_capsule.h"

double copysign(double x, double y) {
    unsigned long long xb;
    unsigned long long yb;
    __builtin_memcpy(&xb, &x, sizeof(xb));
    __builtin_memcpy(&yb, &y, sizeof(yb));
    xb = (xb & 0x7fffffffffffffffull) | (yb & 0x8000000000000000ull);
    __builtin_memcpy(&x, &xb, sizeof(x));
    return x;
}

// Unfused (double-rounding) like the rest of this file; llvm.fmuladd permits
// exactly this.
double fma(double a, double b, double c) {
    return a * b + c;
}

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

static double positive_infinity(void) {
    unsigned long long bits = 0x7ff0000000000000ull;
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
    // Halving the encoded exponent provides a scale-correct seed across the
    // complete normal range. Normalize subnormals first so the same bit
    // construction remains valid, then undo sqrt(2^54) at the end.
    unsigned long long bits = double_bits(x);
    int subnormal = !(bits & 0x7ff0000000000000ull);
    if (subnormal) {
        x = x * 18014398509481984.0; // 2^54
        bits = double_bits(x);
    }
    bits = (bits >> 1) + 0x1ff8000000000000ull;
    double g;
    __builtin_memcpy(&g, &bits, sizeof(g));
    for (int i = 0; i < 12; i++) {
        double n = (g + x / g) / 2.0;
        if (n == g) {
            break;
        }
        g = n;
    }
    return subnormal ? g / 134217728.0 : g; // 2^27
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

// The transcendentals, by compact series. Every operation below becomes
// integer work once bpf-soft-float rewrites it, so these are as available here
// as addition is. They are approximations, with explicit range reduction and
// special-value handling rather than a correctly-rounded libm contract.
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
    if (a == 1.0) {
        return 1.0;
    }
    if (b != b) {
        return b;
    }
    if (a == -1.0 && infinite(b)) {
        return 1.0;
    }
    if (a == 0.0) {
        int negative_odd = (double_bits(a) >> 63) && fabs(b) < 9007199254740992.0 && trunc(b) == b && ((long long)b & 1);
        if (b < 0.0) {
            return copysign(positive_infinity(), negative_odd ? -1.0 : 1.0);
        }
        return copysign(0.0, negative_odd ? -1.0 : 1.0);
    }
    if (a < 0.0) {
        if (trunc(b) != b) {
            return quiet_nan();
        }
        double r = exp(b * log(-a));
        int odd = fabs(b) < 9007199254740992.0 && ((long long)b & 1);
        return odd ? -r : r;
    }
    return exp(b * log(a));
}
double atan(double x) {
    if (x != x) {
        return x;
    }
    double sign = 1.0;
    if (x < 0.0) {
        sign = -1.0;
        x = -x;
    }
    int invert = 0;
    if (x > 1.0) {
        invert = 1;
        x = 1.0 / x;
    }
    // Three half-angle reductions (atan(x) = 2 atan(x / (1 + sqrt(1 + x^2))))
    // pull the argument under ~0.14, where the nine-term odd Taylor series is
    // a useful compact approximation.
    int halvings;
    for (halvings = 0; halvings < 3; halvings++) {
        x = x / (1.0 + sqrt(1.0 + x * x));
    }
    static const double coeff[] = {
        1.0 / 17.0,
        -1.0 / 15.0,
        1.0 / 13.0,
        -1.0 / 11.0,
        1.0 / 9.0,
        -1.0 / 7.0,
        1.0 / 5.0,
        -1.0 / 3.0,
        1.0,
    };
    double x2 = x * x;
    double r = coeff[0];
    unsigned i;
    for (i = 1; i < sizeof(coeff) / sizeof(coeff[0]); i++) {
        r = r * x2 + coeff[i];
    }
    r = r * x * 8.0; // undo the three halvings
    if (invert) {
        r = 1.5707963267948966 - r;
    }
    return sign * r;
}

double atan2(double y, double x) {
    if (y != y) {
        return y;
    }
    if (x != x) {
        return x;
    }
    if (x > 0.0) {
        return atan(y / x);
    }
    if (x < 0.0) {
        return y >= 0.0 ? atan(y / x) + PI : atan(y / x) - PI;
    }
    if (y > 0.0) {
        return PI / 2.0;
    }
    if (y < 0.0) {
        return -PI / 2.0;
    }
    return 0.0;
}

double asin(double x) {
    if (x != x || x > 1.0 || x < -1.0) {
        return quiet_nan();
    }
    return atan2(x, sqrt(1.0 - x * x));
}

double acos(double x) {
    if (x != x || x > 1.0 || x < -1.0) {
        return quiet_nan();
    }
    if (x == -1.0) {
        return PI;
    }
    // Half-angle form: stable at both ends of the domain.
    return 2.0 * atan2(sqrt(1.0 - x * x), 1.0 + x);
}
double difftime(long a, long b) {
    return (double)a - (double)b;
}
double strtod(const char* s, char** end) {
    // Deliberate stub: see the text-to-float limitation in README.md.
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
float copysignf(float x, float y) {
    return (float)copysign(x, y);
}
float fmaf(float a, float b, float c) {
    return (float)fma(a, b, c);
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
    if (x == 0.0 || x != x || infinite(x)) {
        return x;
    }
    double magnitude = fabs(x);
    double result = magnitude > 1.0e154 ? log(magnitude) + LN2 : log(magnitude + sqrt(magnitude * magnitude + 1.0));
    return x < 0.0 ? -result : result;
}
double acosh(double x) {
    if (x > 1.0e154) {
        return log(x) + LN2;
    }
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
    a = fabs(a);
    b = fabs(b);
    if (infinite(a) || infinite(b)) {
        return positive_infinity();
    }
    if (a < b) {
        double swap = a;
        a = b;
        b = swap;
    }
    if (a == 0.0) {
        return a;
    }
    double ratio = b / a;
    return a * sqrt(1.0 + ratio * ratio);
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
    if (a == b) {
        return a == 0.0 && (double_bits(a) >> 63) ? a : b;
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
    if (a == b) {
        return a == 0.0 && (double_bits(a) >> 63) ? b : a;
    }
    return a > b ? a : b;
}

static double round_to_even(double x) {
    if (x == 0.0 || x != x || infinite(x) || fabs(x) >= 4503599627370496.0) {
        return x;
    }
    double lower = floor(x);
    double fraction = x - lower;
    double result = lower;
    if (fraction > 0.5 || (fraction == 0.5 && ((long long)lower & 1))) {
        result = lower + 1.0;
    }
    return result == 0.0 ? copysign(0.0, x) : result;
}

double nearbyint(double x) {
    return round_to_even(x);
}
double rint(double x) {
    return round_to_even(x);
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
    return (long)round_to_even(x);
}
long long llrint(double x) {
    return (long long)round_to_even(x);
}
