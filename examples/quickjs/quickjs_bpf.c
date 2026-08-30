// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Stock QuickJS in the kernel. Scripts and batch stdin come from Capsule
// memory; console output and uncaught exceptions go back to it.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <string.h>

#include "bpf_capsule.h"

#include "quickjs.h"
#include "quickjs_ctrl.h"

struct quickjs_bpf_ctrl qctrl SEC(".data.qctrl");

struct qjs_input {
    const char* data;
    size_t size;
    size_t cursor;
};

static struct qjs_input qjs_input;

// Sizes keep counting past the capacity so the host can report truncation.
static size_t qjs_append(char* buffer, size_t capacity, size_t begin, const char* text, size_t length) {
    size_t copied = begin < capacity ? capacity - begin : 0;
    if (copied > length) {
        copied = length;
    }
    if (copied) {
        memcpy(buffer + begin, text, copied);
    }
    return length > SIZE_MAX - begin ? SIZE_MAX : begin + length;
}

static void qjs_out(const char* text, size_t length) {
    qctrl.output.size = qjs_append(qctrl.output.address, qctrl.output.capacity, qctrl.output.size, text, length);
}

static JSValue qjs_console_log(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    for (int index = 0; index < argument_count; ++index) {
        size_t length = 0;
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

static JSValue qjs_buffer_read(JSContext* context) {
    JSValue text = JS_NewStringLen(context, qjs_input.data + qjs_input.cursor, qjs_input.size - qjs_input.cursor);
    qjs_input.cursor = qjs_input.size;
    return text;
}

static JSValue qjs_buffer_read_line(JSContext* context) {
    if (qjs_input.cursor >= qjs_input.size) {
        return JS_NULL;
    }
    size_t line_end = qjs_input.cursor;
    while (line_end < qjs_input.size && qjs_input.data[line_end] != '\n') {
        ++line_end;
    }
    JSValue line = JS_NewStringLen(context, qjs_input.data + qjs_input.cursor, line_end - qjs_input.cursor);
    qjs_input.cursor = line_end < qjs_input.size ? line_end + 1 : line_end;
    return line;
}

static JSValue qjs_read(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    (void)argument_count;
    (void)arguments;
    return qjs_buffer_read(context);
}

static JSValue qjs_read_line(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    (void)argument_count;
    (void)arguments;
    return qjs_buffer_read_line(context);
}

static void qjs_install_globals(JSContext* context) {
    JSValue global = JS_GetGlobalObject(context);
    JSValue console = JS_NewObject(context);
    JS_SetPropertyStr(context, console, "log", JS_NewCFunction(context, qjs_console_log, "log", 1));
    JS_SetPropertyStr(context, global, "console", console);
    JS_SetPropertyStr(context, global, "read", JS_NewCFunction(context, qjs_read, "read", 0));
    JS_SetPropertyStr(context, global, "readLine", JS_NewCFunction(context, qjs_read_line, "readLine", 0));
    JS_FreeValue(context, global);
}

// Record the failure the way a command-line engine would report it, then
// exit(1): an uncaught exception ends the whole script run.
static __attribute__((noreturn)) void qjs_fail(const char* fallback, JSRuntime* runtime, JSContext* context) {
    const char* text = fallback;
    size_t length = 0;
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
    qctrl.error.size = qjs_append(qctrl.error.address, qctrl.error.capacity, qctrl.error.size, text, length);
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
    if (!qctrl.script.address || qctrl.script.size >= qctrl.script.capacity || !qctrl.input.address || qctrl.input.size > qctrl.input.capacity ||
        !qctrl.output.address || !qctrl.output.capacity || !qctrl.error.address || !qctrl.error.capacity) {
        capsule_exit(1);
    }
    qjs_input.data = qctrl.input.address;
    qjs_input.size = qctrl.input.size;
    qjs_input.cursor = 0;

    JSRuntime* runtime = JS_NewRuntime();
    JSContext* context = runtime ? JS_NewContext(runtime) : 0;
    if (!context) {
        qjs_fail("cannot create QuickJS context", runtime, 0);
    }
    qjs_install_globals(context);
    JSValue value = JS_Eval(context, qctrl.script.address, qctrl.script.size, "bpf.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(value)) {
        JS_FreeValue(context, value);
        qjs_fail("QuickJS evaluation failed", runtime, context);
    }
    JS_FreeValue(context, value);
    JS_FreeContext(context);
    JS_FreeRuntime(runtime);
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
