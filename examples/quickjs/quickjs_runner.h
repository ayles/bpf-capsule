// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The script runner shared by the Capsule guest and the native comparison
// build: stock QuickJS with console.log, read() and readLine() over buffers,
// and the uncaught exception recorded the way a command-line engine reports
// it. Both builds include this file once; only where the buffers live differs.
#pragma once

#include <stdint.h>
#include <string.h>

#include "quickjs.h"

#include "quickjs_ctrl.h"

static struct qjs_buffer* qjs_runner_output;

static struct {
    const char* data;
    size_t size;
    size_t cursor;
} qjs_runner_input;

// Sizes keep counting past the capacity so the host can report truncation.
static void qjs_runner_append(struct qjs_buffer* buffer, const char* text, size_t length) {
    size_t begin = buffer->size;
    size_t copied = begin < buffer->capacity ? buffer->capacity - begin : 0;
    if (copied > length) {
        copied = length;
    }
    if (copied) {
        memcpy(buffer->address + begin, text, copied);
    }
    buffer->size = length > SIZE_MAX - begin ? SIZE_MAX : begin + length;
}

static JSValue qjs_runner_console_log(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    for (int index = 0; index < argument_count; ++index) {
        size_t length = 0;
        const char* text = JS_ToCStringLen(context, &length, arguments[index]);
        if (!text) {
            return JS_EXCEPTION;
        }
        if (index) {
            qjs_runner_append(qjs_runner_output, " ", 1);
        }
        qjs_runner_append(qjs_runner_output, text, length);
        JS_FreeCString(context, text);
    }
    qjs_runner_append(qjs_runner_output, "\n", 1);
    return JS_UNDEFINED;
}

static JSValue qjs_runner_read(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    (void)argument_count;
    (void)arguments;
    JSValue text = JS_NewStringLen(context, qjs_runner_input.data + qjs_runner_input.cursor, qjs_runner_input.size - qjs_runner_input.cursor);
    qjs_runner_input.cursor = qjs_runner_input.size;
    return text;
}

static JSValue qjs_runner_read_line(JSContext* context, JSValueConst this_value, int argument_count, JSValueConst* arguments) {
    (void)this_value;
    (void)argument_count;
    (void)arguments;
    if (qjs_runner_input.cursor >= qjs_runner_input.size) {
        return JS_NULL;
    }
    size_t line_end = qjs_runner_input.cursor;
    while (line_end < qjs_runner_input.size && qjs_runner_input.data[line_end] != '\n') {
        ++line_end;
    }
    JSValue line = JS_NewStringLen(context, qjs_runner_input.data + qjs_runner_input.cursor, line_end - qjs_runner_input.cursor);
    qjs_runner_input.cursor = line_end < qjs_runner_input.size ? line_end + 1 : line_end;
    return line;
}

static void qjs_runner_install_globals(JSContext* context) {
    JSValue global = JS_GetGlobalObject(context);
    JSValue console = JS_NewObject(context);
    JS_SetPropertyStr(context, console, "log", JS_NewCFunction(context, qjs_runner_console_log, "log", 1));
    JS_SetPropertyStr(context, global, "console", console);
    JS_SetPropertyStr(context, global, "read", JS_NewCFunction(context, qjs_runner_read, "read", 0));
    JS_SetPropertyStr(context, global, "readLine", JS_NewCFunction(context, qjs_runner_read_line, "readLine", 0));
    JS_FreeValue(context, global);
}

// Records the failure and releases the engine. Returns 1 for the caller.
static int qjs_runner_fail(const char* fallback, JSRuntime* runtime, JSContext* context, struct qjs_buffer* error) {
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
        length = strlen(text);
    }
    qjs_runner_append(error, text, length);
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
    return 1;
}

// Runs the NUL-terminated script. Returns 0, or 1 with the message in the
// error buffer.
static int qjs_runner_run(const struct qjs_buffer* script, const struct qjs_buffer* input, struct qjs_buffer* output, struct qjs_buffer* error) {
    qjs_runner_output = output;
    output->size = 0;
    error->size = 0;
    qjs_runner_input.data = input->address;
    qjs_runner_input.size = input->size;
    qjs_runner_input.cursor = 0;

    JSRuntime* runtime = JS_NewRuntime();
    JSContext* context = runtime ? JS_NewContext(runtime) : 0;
    if (!context) {
        return qjs_runner_fail("cannot create QuickJS context", runtime, 0, error);
    }
    qjs_runner_install_globals(context);
    JSValue value = JS_Eval(context, script->address, script->size, "script.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(value)) {
        JS_FreeValue(context, value);
        return qjs_runner_fail("QuickJS evaluation failed", runtime, context, error);
    }
    JS_FreeValue(context, value);
    JS_FreeContext(context);
    JS_FreeRuntime(runtime);
    return 0;
}
