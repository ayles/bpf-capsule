// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Batch stdin for scripts: read() returns the whole remaining input,
// readLine() the next line or null. Shared verbatim by the Capsule guest and
// the --native engine run so both see identical bytes, and both register
// their console.log through the same installer.
#pragma once

#include "quickjs.h"

struct qjs_buffer_input {
    const char* data;
    unsigned long size;
    unsigned long cursor;
};

static JSValue qjs_buffer_read(JSContext* context, struct qjs_buffer_input* input) {
    JSValue text = JS_NewStringLen(context, input->data + input->cursor, input->size - input->cursor);
    input->cursor = input->size;
    return text;
}

static JSValue qjs_buffer_read_line(JSContext* context, struct qjs_buffer_input* input) {
    if (input->cursor >= input->size) {
        return JS_NULL;
    }
    unsigned long line_end = input->cursor;
    while (line_end < input->size && input->data[line_end] != '\n') {
        ++line_end;
    }
    JSValue line = JS_NewStringLen(context, input->data + input->cursor, line_end - input->cursor);
    input->cursor = line_end < input->size ? line_end + 1 : line_end;
    return line;
}

// A failure here is an out-of-memory event this early interpreter setup does
// not try to survive; JS_SetPropertyStr consumes values even then.
static void qjs_install_globals(JSContext* context, JSCFunction* log, JSCFunction* read, JSCFunction* read_line) {
    JSValue global = JS_GetGlobalObject(context);
    JSValue console = JS_NewObject(context);
    JS_SetPropertyStr(context, console, "log", JS_NewCFunction(context, log, "log", 1));
    JS_SetPropertyStr(context, global, "console", console);
    JS_SetPropertyStr(context, global, "read", JS_NewCFunction(context, read, "read", 0));
    JS_SetPropertyStr(context, global, "readLine", JS_NewCFunction(context, read_line, "readLine", 0));
    JS_FreeValue(context, global);
}
