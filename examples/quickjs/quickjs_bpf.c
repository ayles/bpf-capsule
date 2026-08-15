// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// JavaScript in the kernel — QuickJS, unmodified, through the same pipeline.
//
// Every JavaScript number is a double, so this is the port that leans hardest
// on bpf-soft-float: the interpreter's arithmetic, its number formatting and
// its property lookups all end up as integer work. Batch stdin goes in,
// console.log text and any uncaught exception come back out, all through
// guest-owned buffers in Capsule memory.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include <stdint.h>

#include "quickjs.h"
#include "quickjs_ctrl.h"
#include "quickjs_io.h"

struct quickjs_bpf_ctrl qctrl SEC(".data.qctrl");

// Ordinary unsectioned storage: Capsule picks the kernel representation and
// keeps the zero-filled bytes out of the object image.
static char qjs_script_buf[256 << 10];
static char qjs_input_buf[256 << 10];
static char qjs_output_buf[1 << 20];
static char qjs_error_buf[64 << 10];

static struct qjs_buffer_input qjs_input;

static void quickjs_prepare_body(void) {
    qctrl.script.address = (uint64_t)(void*)qjs_script_buf;
    qctrl.script.capacity = sizeof(qjs_script_buf);
    qctrl.input.address = (uint64_t)(void*)qjs_input_buf;
    qctrl.input.capacity = sizeof(qjs_input_buf);
    qctrl.output.address = (uint64_t)(void*)qjs_output_buf;
    qctrl.output.capacity = sizeof(qjs_output_buf);
    qctrl.error.address = (uint64_t)(void*)qjs_error_buf;
    qctrl.error.capacity = sizeof(qjs_error_buf);
}

// Sizes keep counting past the capacity so the host can report truncation.
// The new size comes back as a value: a pointer into the sectioned control
// map must not cross the managed call boundary.
static uint64_t qjs_append(char* buffer, uint64_t capacity, uint64_t begin, const char* text, unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        if (begin + index < capacity) {
            buffer[begin + index] = text[index];
        }
    }
    return begin + length;
}

static void qjs_out(const char* text, unsigned long length) {
    qctrl.output.size = qjs_append(qjs_output_buf, sizeof(qjs_output_buf), qctrl.output.size, text, length);
}

static JSValue qjs_console_log(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    for (int index = 0; index < argument_count; ++index) {
        unsigned long length = 0;
        const char* text = JS_ToCStringLen(context, &length, arguments[index]);
        if (!text) {
            return JS_EXCEPTION;
        }
        if (index) {
            qjs_out(" ", 1);
        }
        qjs_out(text, length);
        JS_FreeCString(context, text);
    }
    qjs_out("\n", 1);
    return JS_UNDEFINED;
}

static JSValue qjs_read(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    (void)argument_count;
    (void)arguments;
    return qjs_buffer_read(context, &qjs_input);
}

static JSValue qjs_read_line(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    (void)argument_count;
    (void)arguments;
    return qjs_buffer_read_line(context, &qjs_input);
}

// Record the failure the way a command-line engine would report it, then
// exit(1): an uncaught exception ends the whole script run.
static __attribute__((noreturn)) void qjs_fail(const char* fallback, JSRuntime* runtime, JSContext* context) {
    const char* text = fallback;
    unsigned long length = 0;
    JSValue exception = JS_UNDEFINED;
    if (context) {
        exception = JS_GetException(context);
        text = JS_ToCStringLen(context, &length, exception);
        if (!text) {
            text = fallback;
        }
    }
    if (!length) {
        while (text[length]) {
            ++length;
        }
    }
    qctrl.error.size = qjs_append(qjs_error_buf, sizeof(qjs_error_buf), qctrl.error.size, text, length);
    if (context) {
        if (text != fallback) {
            JS_FreeCString(context, text);
        }
        JS_FreeValue(context, exception);
        JS_FreeContext(context);
    }
    if (runtime) {
        JS_FreeRuntime(runtime);
    }
    capsule_exit(1);
}

static void quickjs_run_body(void) {
    qctrl.output.size = 0;
    qctrl.error.size = 0;
    qjs_input.data = qjs_input_buf;
    qjs_input.size = (unsigned long)qctrl.input.size;
    qjs_input.cursor = 0;

    JSRuntime* runtime = JS_NewRuntime();
    JSContext* context = runtime ? JS_NewContext(runtime) : 0;
    if (!context) {
        qjs_fail("cannot create QuickJS context", runtime, 0);
    }
    qjs_install_globals(context, qjs_console_log, qjs_read, qjs_read_line);
    JSValue value = JS_Eval(context, qjs_script_buf, qctrl.script.size, "bpf.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(value)) {
        JS_FreeValue(context, value);
        qjs_fail("QuickJS evaluation failed", runtime, context);
    }
    JS_FreeValue(context, value);
    JS_FreeContext(context);
    JS_FreeRuntime(runtime);
}

SEC("syscall")
int quickjs_prepare(void) {
    qctrl.capsule = capsule_call_void(quickjs_prepare_body);
    return 0;
}

SEC("syscall")
int quickjs_run(void) {
    qctrl.capsule = capsule_call_void(quickjs_run_body);
    return 0;
}

SEC("syscall")
int quickjs_drain(void) {
    qctrl.capsule = capsule_continue_void(qctrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
