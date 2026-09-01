/*
 * Adapted from musl's src/internal/floatscan.c and src/stdlib/strtod.c.
 * The FILE scanner is replaced by a cursor over a NUL-terminated string and
 * the long-double variants are removed. Decimal conversion follows musl;
 * hexadecimal conversion uses integer guard and sticky bits because the BPF
 * ABI has no extended-precision long double.
 *
 * Copyright (c) 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#define FS_MANT_DIG __DBL_MANT_DIG__
#define FS_MIN_EXP __DBL_MIN_EXP__
#define FS_MAX __DBL_MAX__
#define FS_MIN __DBL_MIN__
#define FS_EPSILON __DBL_EPSILON__

#define FS_B1B_DIG 2
#define FS_KMAX 128
#define FS_MASK (FS_KMAX - 1)

struct fs_scan {
    const char* start;
    const char* cursor;
};

static int fs_get(struct fs_scan* scan) {
    return (unsigned char)*scan->cursor++;
}

static void fs_unget(struct fs_scan* scan) {
    if (scan->cursor > scan->start) {
        scan->cursor--;
    }
}

static long long fs_scan_exponent(struct fs_scan* scan) {
    int c = fs_get(scan);
    int negative = 0;
    if (c == '+' || c == '-') {
        negative = c == '-';
        c = fs_get(scan);
        if ((unsigned int)(c - '0') >= 10u) {
            fs_unget(scan);
        }
    }
    if ((unsigned int)(c - '0') >= 10u) {
        fs_unget(scan);
        return LLONG_MIN;
    }

    int small = 0;
    while ((unsigned int)(c - '0') < 10u && small < INT_MAX / 10) {
        small = 10 * small + c - '0';
        c = fs_get(scan);
    }
    long long result = small;
    while ((unsigned int)(c - '0') < 10u && result < LLONG_MAX / 100) {
        result = 10 * result + c - '0';
        c = fs_get(scan);
    }
    while ((unsigned int)(c - '0') < 10u) {
        c = fs_get(scan);
    }
    fs_unget(scan);
    return negative ? -result : result;
}

static long long fs_saturating_add(long long left, long long right) {
    if (right > 0 && left > LLONG_MAX - right) {
        return LLONG_MAX;
    }
    if (right < 0 && left < LLONG_MIN - right) {
        return LLONG_MIN;
    }
    return left + right;
}

static double fs_decimal(struct fs_scan* scan, int c, int sign) {
    uint32_t digits[FS_KMAX];
    static const uint32_t threshold[FS_B1B_DIG] = {9007199, 254740991};
    static const int powers_of_ten[] = {10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
    int i;
    int j = 0;
    int k = 0;
    int first;
    int end;
    long long radix_position = 0;
    long long digit_count = 0;
    long long exponent10 = 0;
    int last_nonzero = 0;
    int got_digit = 0;
    int got_radix = 0;

    for (; c == '0'; c = fs_get(scan)) {
        got_digit = 1;
    }
    if (c == '.') {
        got_radix = 1;
        for (c = fs_get(scan); c == '0'; c = fs_get(scan)) {
            got_digit = 1;
            radix_position--;
        }
    }

    digits[0] = 0;
    for (; (unsigned int)(c - '0') < 10u || c == '.'; c = fs_get(scan)) {
        if (c == '.') {
            if (got_radix) {
                break;
            }
            got_radix = 1;
            radix_position = digit_count;
        } else if (k < FS_KMAX - 3) {
            digit_count++;
            if (c != '0') {
                last_nonzero = (int)digit_count;
            }
            if (j) {
                digits[k] = digits[k] * 10 + (uint32_t)(c - '0');
            } else {
                digits[k] = (uint32_t)(c - '0');
            }
            if (++j == 9) {
                k++;
                j = 0;
            }
            got_digit = 1;
        } else {
            digit_count++;
            if (c != '0') {
                last_nonzero = (FS_KMAX - 4) * 9;
                digits[FS_KMAX - 4] |= 1;
            }
        }
    }
    if (!got_radix) {
        radix_position = digit_count;
    }

    if (got_digit && (c | 32) == 'e') {
        exponent10 = fs_scan_exponent(scan);
        if (exponent10 == LLONG_MIN) {
            fs_unget(scan);
            exponent10 = 0;
        }
        radix_position = fs_saturating_add(radix_position, exponent10);
    } else {
        fs_unget(scan);
    }
    if (!got_digit) {
        scan->cursor = scan->start;
        return 0.0;
    }
    if (!digits[0]) {
        return sign * 0.0;
    }

    const int bits = FS_MANT_DIG;
    const int minimum_exponent = FS_MIN_EXP - bits;
    const int maximum_exponent = -minimum_exponent - bits + 3;
    if (radix_position == digit_count && digit_count < 10) {
        return sign * (double)digits[0];
    }
    if (radix_position > -minimum_exponent / 2) {
        errno = ERANGE;
        return sign * FS_MAX * FS_MAX;
    }
    if (radix_position < minimum_exponent - 2 * FS_MANT_DIG) {
        errno = ERANGE;
        return sign * FS_MIN * FS_MIN;
    }

    if (j) {
        for (; j < 9; j++) {
            digits[k] *= 10;
        }
        k++;
    }

    first = 0;
    end = k;
    int exponent2 = 0;
    int radix = (int)radix_position;

    if (last_nonzero < 9 && last_nonzero <= radix && radix < 18) {
        if (radix == 9) {
            return sign * (double)digits[0];
        }
        if (radix < 9) {
            return sign * (double)digits[0] / powers_of_ten[8 - radix];
        }
        int bit_limit = bits - 3 * (radix - 9);
        if (bit_limit > 30 || digits[0] >> bit_limit == 0) {
            return sign * (double)digits[0] * powers_of_ten[radix - 10];
        }
    }

    while (!digits[end - 1]) {
        end--;
    }

    if (radix % 9) {
        int remainder = radix >= 0 ? radix % 9 : radix % 9 + 9;
        int divisor = powers_of_ten[8 - remainder];
        uint32_t carry = 0;
        for (k = first; k != end; k++) {
            uint32_t next = digits[k] % (uint32_t)divisor;
            digits[k] = digits[k] / (uint32_t)divisor + carry;
            carry = (uint32_t)(1000000000 / divisor) * next;
            if (k == first && !digits[k]) {
                first = (first + 1) & FS_MASK;
                radix -= 9;
            }
        }
        if (carry) {
            digits[end++] = carry;
        }
        radix += 9 - remainder;
    }

    while (radix < 9 * FS_B1B_DIG || (radix == 9 * FS_B1B_DIG && digits[first] < threshold[0])) {
        uint32_t carry = 0;
        exponent2 -= 29;
        for (k = (end - 1) & FS_MASK;; k = (k - 1) & FS_MASK) {
            uint64_t value = ((uint64_t)digits[k] << 29) + carry;
            if (value > 1000000000) {
                carry = (uint32_t)(value / 1000000000);
                digits[k] = (uint32_t)(value % 1000000000);
            } else {
                carry = 0;
                digits[k] = (uint32_t)value;
            }
            if (k == ((end - 1) & FS_MASK) && k != first && !digits[k]) {
                end = k;
            }
            if (k == first) {
                break;
            }
        }
        if (carry) {
            radix += 9;
            first = (first - 1) & FS_MASK;
            if (first == end) {
                end = (end - 1) & FS_MASK;
                digits[(end - 1) & FS_MASK] |= digits[end];
            }
            digits[first] = carry;
        }
    }

    for (;;) {
        uint32_t carry = 0;
        int shift = 1;
        for (i = 0; i < FS_B1B_DIG; i++) {
            k = (first + i) & FS_MASK;
            if (k == end || digits[k] < threshold[i]) {
                i = FS_B1B_DIG;
                break;
            }
            if (digits[k] > threshold[i]) {
                break;
            }
        }
        if (i == FS_B1B_DIG && radix == 9 * FS_B1B_DIG) {
            break;
        }
        if (radix > 9 + 9 * FS_B1B_DIG) {
            shift = 9;
        }
        exponent2 += shift;
        for (k = first; k != end; k = (k + 1) & FS_MASK) {
            uint32_t next = digits[k] & ((1u << shift) - 1u);
            digits[k] = (digits[k] >> shift) + carry;
            carry = (1000000000u >> shift) * next;
            if (k == first && !digits[k]) {
                first = (first + 1) & FS_MASK;
                i--;
                radix -= 9;
            }
        }
        if (carry) {
            if (((end + 1) & FS_MASK) != first) {
                digits[end] = carry;
                end = (end + 1) & FS_MASK;
            } else {
                digits[(end - 1) & FS_MASK] |= 1;
            }
        }
    }

    double value = 0.0;
    for (i = 0; i < FS_B1B_DIG; i++) {
        if (((first + i) & FS_MASK) == end) {
            end = (end + 1) & FS_MASK;
            digits[(end - 1) & FS_MASK] = 0;
        }
        value = 1000000000.0 * value + digits[(first + i) & FS_MASK];
    }
    value *= sign;

    int rounded_bits = bits;
    int denormal = 0;
    if (rounded_bits > FS_MANT_DIG + exponent2 - minimum_exponent) {
        rounded_bits = FS_MANT_DIG + exponent2 - minimum_exponent;
        if (rounded_bits < 0) {
            rounded_bits = 0;
        }
        denormal = 1;
    }

    double fraction = 0.0;
    double bias = 0.0;
    if (rounded_bits < FS_MANT_DIG) {
        bias = copysign(ldexp(1.0, 2 * FS_MANT_DIG - rounded_bits - 1), value);
        fraction = fmod(value, ldexp(1.0, FS_MANT_DIG - rounded_bits));
        value -= fraction;
        value += bias;
    }

    if (((first + i) & FS_MASK) != end) {
        uint32_t tail = digits[(first + i) & FS_MASK];
        if (tail < 500000000 && (tail || ((first + i + 1) & FS_MASK) != end)) {
            fraction += 0.25 * sign;
        } else if (tail > 500000000) {
            fraction += 0.75 * sign;
        } else if (((first + i + 1) & FS_MASK) == end) {
            fraction += 0.5 * sign;
        } else {
            fraction += 0.75 * sign;
        }
        if (FS_MANT_DIG - rounded_bits >= 2 && !fmod(fraction, 1.0)) {
            fraction++;
        }
    }

    value += fraction;
    value -= bias;

    if (((exponent2 + FS_MANT_DIG) & INT_MAX) > maximum_exponent - 5) {
        if (fabs(value) >= 2.0 / FS_EPSILON) {
            if (denormal && rounded_bits == FS_MANT_DIG + exponent2 - minimum_exponent) {
                denormal = 0;
            }
            value *= 0.5;
            exponent2++;
        }
        if (exponent2 + FS_MANT_DIG > maximum_exponent || (denormal && fraction)) {
            errno = ERANGE;
        }
    }

    return ldexp(value, exponent2);
}

static int fs_hex_digit(int c) {
    if ((unsigned int)(c - '0') < 10u) {
        return c - '0';
    }
    c |= 32;
    return (unsigned int)(c - 'a') < 6u ? c - 'a' + 10 : -1;
}

static unsigned int fs_bit_length(uint64_t value) {
    return 64u - (unsigned int)__builtin_clzll(value);
}

static double fs_from_bits(uint64_t magnitude, int sign) {
    uint64_t bits = magnitude | (sign < 0 ? UINT64_C(0x8000000000000000) : 0);
    double value;
    __builtin_memcpy(&value, &bits, sizeof(value));
    return value;
}

// Hexadecimal input already describes a binary rational, so convert it with
// integer guard and sticky bits. This avoids depending on extra long-double
// precision (the BPF ABI intentionally has 64-bit long double).
static double fs_hexadecimal(struct fs_scan* scan, int sign) {
    const char* after_prefix = scan->cursor;
    uint64_t significand = 0;
    unsigned int kept_digits = 0;
    unsigned long long digit_count = 0;
    unsigned long long radix_position = 0;
    unsigned long long first_nonzero = 0;
    int saw_digit = 0;
    int saw_radix = 0;
    int saw_nonzero = 0;
    int sticky = 0;
    int c = fs_get(scan);

    for (;;) {
        int digit = fs_hex_digit(c);
        if (digit >= 0) {
            saw_digit = 1;
            if (!saw_nonzero && digit) {
                saw_nonzero = 1;
                first_nonzero = digit_count;
            }
            if (saw_nonzero) {
                if (kept_digits < 16) {
                    significand = (significand << 4) | (unsigned int)digit;
                    kept_digits++;
                } else if (digit) {
                    sticky = 1;
                }
            }
            digit_count++;
        } else if (c == '.' && !saw_radix) {
            saw_radix = 1;
            radix_position = digit_count;
        } else {
            break;
        }
        c = fs_get(scan);
    }

    if (!saw_digit) {
        scan->cursor = after_prefix - 1; // consume the leading zero, not "x"
        return sign * 0.0;
    }
    if (!saw_radix) {
        radix_position = digit_count;
    }

    long long parsed_exponent = 0;
    if ((c | 32) == 'p') {
        parsed_exponent = fs_scan_exponent(scan);
        if (parsed_exponent == LLONG_MIN) {
            fs_unget(scan);
            parsed_exponent = 0;
        }
    } else {
        fs_unget(scan);
    }
    if (!saw_nonzero) {
        return fs_from_bits(0, sign);
    }

    long long scale_digits;
    if (radix_position >= first_nonzero + kept_digits) {
        unsigned long long distance = radix_position - first_nonzero - kept_digits;
        if (distance > (unsigned long long)LLONG_MAX / 4u) {
            errno = ERANGE;
            return fs_from_bits(UINT64_C(0x7ff0000000000000), sign);
        }
        scale_digits = (long long)distance;
    } else {
        unsigned long long distance = first_nonzero + kept_digits - radix_position;
        if (distance > (unsigned long long)LLONG_MAX / 4u) {
            errno = ERANGE;
            return fs_from_bits(0, sign);
        }
        scale_digits = -(long long)distance;
    }
    long long exponent2;
    if (scale_digits > 0 && parsed_exponent > LLONG_MAX - scale_digits * 4) {
        exponent2 = LLONG_MAX;
    } else if (scale_digits < 0 && parsed_exponent < LLONG_MIN - scale_digits * 4) {
        exponent2 = LLONG_MIN;
    } else {
        exponent2 = parsed_exponent + scale_digits * 4;
    }

    unsigned int significant_bits = fs_bit_length(significand);
    long long top_exponent = exponent2 > LLONG_MAX - (long long)significant_bits + 1 ? LLONG_MAX : exponent2 + significant_bits - 1;
    if (top_exponent > 1023) {
        errno = ERANGE;
        return fs_from_bits(UINT64_C(0x7ff0000000000000), sign);
    }
    if (top_exponent < -1075) {
        errno = ERANGE;
        return fs_from_bits(0, sign);
    }

    if (top_exponent >= -1022) {
        unsigned int discarded_bits = significant_bits > 53 ? significant_bits - 53 : 0;
        uint64_t rounded = discarded_bits ? significand >> discarded_bits : significand << (53 - significant_bits);
        if (discarded_bits) {
            uint64_t remainder = significand & ((UINT64_C(1) << discarded_bits) - 1);
            uint64_t halfway = UINT64_C(1) << (discarded_bits - 1);
            if (remainder > halfway || (remainder == halfway && (sticky || (rounded & 1)))) {
                rounded++;
            }
        }
        if (rounded == (UINT64_C(1) << 53)) {
            rounded >>= 1;
            top_exponent++;
            if (top_exponent > 1023) {
                errno = ERANGE;
                return fs_from_bits(UINT64_C(0x7ff0000000000000), sign);
            }
        }
        uint64_t exponent_field = (uint64_t)(top_exponent + 1023) << 52;
        return fs_from_bits(exponent_field | (rounded & UINT64_C(0x000fffffffffffff)), sign);
    }

    // Subnormals are integer multiples of 2^-1074. Round the exact rational
    // directly to that unit; a carry of 2^52 naturally becomes DBL_MIN.
    long long discard = -1074 - exponent2;
    uint64_t rounded = 0;
    int inexact = sticky;
    if (discard <= 0) {
        rounded = significand << (unsigned int)-discard;
    } else if (discard < 64) {
        rounded = significand >> discard;
        uint64_t remainder = significand & ((UINT64_C(1) << discard) - 1);
        uint64_t halfway = UINT64_C(1) << (discard - 1);
        inexact |= remainder != 0;
        if (remainder > halfway || (remainder == halfway && (sticky || (rounded & 1)))) {
            rounded++;
        }
    } else if (discard == 64) {
        uint64_t halfway = UINT64_C(1) << 63;
        inexact |= significand != 0;
        if (significand > halfway || (significand == halfway && sticky)) {
            rounded = 1;
        }
    } else {
        inexact = 1;
    }
    if (inexact || !rounded) {
        errno = ERANGE;
    }
    return fs_from_bits(rounded, sign);
}

double strtod(const char* text, char** end) {
    struct fs_scan scan = {.start = text, .cursor = text};
    int sign = 1;
    int c;
    do {
        c = fs_get(&scan);
    } while (isspace(c));

    if (c == '+' || c == '-') {
        sign = c == '-' ? -1 : 1;
        c = fs_get(&scan);
    }

    unsigned int i;
    for (i = 0; i < 8 && (c | 32) == "infinity"[i]; i++) {
        if (i < 7) {
            c = fs_get(&scan);
        }
    }
    if (i == 3 || i == 8 || i > 3) {
        if (i != 8) {
            fs_unget(&scan);
            while (i > 3) {
                fs_unget(&scan);
                i--;
            }
        }
        if (end) {
            *end = (char*)scan.cursor;
        }
        return sign * INFINITY;
    }

    if (!i) {
        for (i = 0; i < 3 && (c | 32) == "nan"[i]; i++) {
            if (i < 2) {
                c = fs_get(&scan);
            }
        }
    }
    if (i == 3) {
        if (fs_get(&scan) != '(') {
            fs_unget(&scan);
        } else {
            const char* payload = scan.cursor;
            for (;;) {
                c = fs_get(&scan);
                if ((unsigned int)(c - '0') < 10u || (unsigned int)(c - 'A') < 26u || (unsigned int)(c - 'a') < 26u || c == '_') {
                    continue;
                }
                if (c == ')') {
                    break;
                }
                scan.cursor = payload - 1;
                break;
            }
        }
        if (end) {
            *end = (char*)scan.cursor;
        }
        return NAN;
    }
    if (i) {
        scan.cursor = scan.start;
        if (end) {
            *end = (char*)text;
        }
        return 0.0;
    }

    double value;
    if (c == '0') {
        c = fs_get(&scan);
        if ((c | 32) == 'x') {
            value = fs_hexadecimal(&scan, sign);
        } else {
            fs_unget(&scan);
            value = fs_decimal(&scan, '0', sign);
        }
    } else {
        value = fs_decimal(&scan, c, sign);
    }
    if (end) {
        *end = (char*)scan.cursor;
    }
    return value;
}
