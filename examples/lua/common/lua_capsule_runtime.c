// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <stdlib.h>

#include "bpf_capsule.h"
#include "lua_capsule_runtime.h"

static void* lua_capsule_allocate(void* user, void* pointer, unsigned long old_size, unsigned long new_size) {
    (void)user;
    (void)old_size;
    if (!new_size) {
        free(pointer);
        return 0;
    }
    return realloc(pointer, new_size);
}

lua_State* lua_capsule_newstate(void* owner) {
    lua_State* state = lua_newstate(lua_capsule_allocate, 0);
    if (state) {
        *(void**)lua_getextraspace(state) = owner;
    }
    return state;
}

void* lua_capsule_owner(lua_State* state) {
    return state ? *(void**)lua_getextraspace(state) : 0;
}

void lua_capsule_throw(void* state_pointer, int status) {
    lua_State* state = (lua_State*)state_pointer;
    const char* message = state ? lua_tostring(state, -1) : 0;
    if (!message) {
        message = "Lua execution failed";
    }
    unsigned long length = 0;
    while (message[length]) {
        ++length;
    }
    lua_capsule_error(state, status, message, length);
    capsule_exit(1);
}
