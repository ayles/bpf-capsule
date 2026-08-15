// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Recursive-descent evaluation of integer arithmetic over an input string.
//
// This file is deliberately ordinary C, and every construct in it is one the
// BPF verifier rejects outright: functions that call themselves, two functions
// that call each other, and loops whose trip counts the input chooses. Stock
// eBPF permits none of that — no recursion at any depth, no loop without a
// bound the verifier can prove — yet nothing here knows or works around it.
// Making this file loadable is the compiler's job, not the program's.
#include "expr.h"

// Any robust recursive parser caps its nesting (Lua does; so does every real
// compiler). The cap is ordinary hygiene, and it also keeps a hostile input
// from running the software call stack out of frames.
// One parenthesis level occupies three mutually-recursive parser frames. A
// cap of 96 therefore fits the 5.15 profile's conservative 384-frame floor,
// including the driver and evaluator frames, instead of accepting an input
// that can only end in a managed-stack abort.
#define EXPR_MAX_NESTING 96

#define EXPR_LLONG_MIN (-9223372036854775807LL - 1)

struct expr_parser {
    const char* src;
    unsigned long len;
    unsigned long pos;
    unsigned long error_at;
    int failed;
    int nesting;
};

// Add, subtract and multiply through unsigned arithmetic so overflow wraps
// instead of being undefined. Both sides of the comparison are Clang, but
// leaning on matching UB would make "kernel equals host" luck rather than a
// property; wrapping makes the results equal by definition.
static int64_t wrap_add(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a + (uint64_t)b);
}

static int64_t wrap_sub(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a - (uint64_t)b);
}

static int64_t wrap_mul(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a * (uint64_t)b);
}

static char peek(struct expr_parser* p) {
    return p->pos < p->len ? p->src[p->pos] : 0;
}

static void skip_spaces(struct expr_parser* p) {
    while (p->pos < p->len && p->src[p->pos] == ' ') {
        p->pos++;
    }
}

static int64_t fail(struct expr_parser* p) {
    if (!p->failed) {
        p->failed = 1;
        p->error_at = p->pos;
    }
    return 0;
}

static int64_t parse_expr(struct expr_parser* p);

static int64_t parse_factor(struct expr_parser* p) {
    skip_spaces(p);
    if (p->failed) {
        return 0;
    }
    if (p->nesting >= EXPR_MAX_NESTING) {
        return fail(p);
    }
    p->nesting++;

    int64_t value;
    char c = peek(p);
    if (c == '(') {
        // The mutual recursion: factor -> expr -> term -> factor, as deep as
        // the input nests parentheses.
        p->pos++;
        value = parse_expr(p);
        skip_spaces(p);
        if (!p->failed && peek(p) == ')') {
            p->pos++;
        } else {
            value = fail(p);
        }
    } else if (c == '-') {
        p->pos++;
        value = wrap_sub(0, parse_factor(p));
    } else if (c >= '0' && c <= '9') {
        // A loop whose trip count is however many digits the input supplies.
        uint64_t magnitude = 0;
        while (p->pos < p->len && p->src[p->pos] >= '0' && p->src[p->pos] <= '9') {
            magnitude = magnitude * 10ull + (uint64_t)(p->src[p->pos] - '0');
            p->pos++;
        }
        value = (int64_t)magnitude;
    } else {
        value = fail(p);
    }

    p->nesting--;
    return value;
}

static int64_t parse_term(struct expr_parser* p) {
    int64_t value = parse_factor(p);
    for (;;) {
        skip_spaces(p);
        char c = peek(p);
        if (p->failed || (c != '*' && c != '/' && c != '%')) {
            return value;
        }
        unsigned long at = p->pos;
        p->pos++;
        int64_t rhs = parse_factor(p);
        if (p->failed) {
            return 0;
        }
        if (c == '*') {
            value = wrap_mul(value, rhs);
            continue;
        }
        // Truncating division is defined C only when the divisor is non-zero
        // and the quotient representable; both violations become an ordinary
        // parse error so kernel and host cannot diverge on undefined cases.
        if (rhs == 0 || (value == EXPR_LLONG_MIN && rhs == -1)) {
            p->failed = 1;
            p->error_at = at;
            return 0;
        }
        value = c == '/' ? value / rhs : value % rhs;
    }
}

static int64_t parse_expr(struct expr_parser* p) {
    int64_t value = parse_term(p);
    for (;;) {
        skip_spaces(p);
        char c = peek(p);
        if (p->failed || (c != '+' && c != '-')) {
            return value;
        }
        p->pos++;
        int64_t rhs = parse_term(p);
        value = c == '+' ? wrap_add(value, rhs) : wrap_sub(value, rhs);
    }
}

int expr_eval(const char* src, unsigned long len, int64_t* value_out, unsigned long* error_at) {
    struct expr_parser p = {
        .src = src,
        .len = len,
        .pos = 0,
        .error_at = 0,
        .failed = 0,
        .nesting = 0,
    };
    int64_t value = parse_expr(&p);
    skip_spaces(&p);
    if (!p.failed && p.pos != p.len) {
        fail(&p); // trailing bytes
    }
    if (p.failed) {
        *error_at = p.error_at;
        return 1;
    }
    *value_out = value;
    return 0;
}
