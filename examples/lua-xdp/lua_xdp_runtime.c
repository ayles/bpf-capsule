// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Per-fiber stock-Lua state and the borrowed XDP packet API.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#include "bpf_capsule.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lua_xdp_internal.h"

struct lua_fiber_state {
    lua_State* state;
    size_t packet_size;
    size_t output_size;
    int script_reference;
};

static struct lua_fiber_state lua_states[BPF_CAPSULE_MAX_FIBERS];

static struct lua_fiber_state* lua_current_state(void) {
    unsigned int index = capsule_fiber_index();
    if (index >= BPF_CAPSULE_MAX_FIBERS || !lua_states[index].state) {
        capsule_exit(1);
    }
    return &lua_states[index];
}

static void lua_exchange_copy(size_t buffer_offset, size_t begin, const char* text, size_t length) {
    size_t available = begin < LUA_XDP_OUTPUT_CAPACITY ? LUA_XDP_OUTPUT_CAPACITY - begin : 0;
    size_t copied = length < available ? length : available;
    for (size_t index = 0; index < copied; ++index) {
        // Read Capsule memory before forming the bounded native-map index.
        // The memory accessor is a global call, and verifier scalar ranges do
        // not survive if LLVM must spill them across that call.
        char byte = text[index];
        // A map-value pointer cannot cross a resumable loop backedge.
        struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
        if (!exchange) {
            capsule_exit(1);
        }
        unsigned long at = (unsigned long)(begin + index);
        // Keep the old verifier's range proof adjacent to the map-value
        // access. Without the barrier, LLVM can reconstruct this index from
        // its unbounded components after restoring a resumable-loop frame.
        asm volatile("" : "+r"(at));
        at &= LUA_XDP_OUTPUT_CAPACITY - 1u;
        asm volatile("" : "+r"(buffer_offset));
        buffer_offset &= LUA_XDP_OUTPUT_CAPACITY;
        ((char*)exchange)[buffer_offset + at] = byte;
    }
}

void lua_capsule_write(const char* text, size_t length) {
    struct lua_fiber_state* fiber = lua_current_state();
    size_t begin = fiber->output_size;
    fiber->output_size += length;
    lua_exchange_copy(0, begin, text, length);
}

static void lua_report_error(lua_State* state) {
    const char* message = lua_tostring(state, -1);
    if (!message) {
        message = "Lua execution failed";
    }
    size_t length = strlen(message);
    struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
    if (!exchange) {
        capsule_exit(1);
    }
    exchange->error_size = length;
    lua_exchange_copy(LUA_XDP_OUTPUT_CAPACITY, 0, message, length);
}

#define LUA_PACKET_METATABLE "bpf.packet"

static size_t lua_packet_start(lua_Integer position, size_t length) {
    if (position > 0) {
        return (size_t)position > length ? length + 1 : (size_t)position;
    }
    if (position == 0 || position < -(lua_Integer)length) {
        return 1;
    }
    return length + (size_t)position + 1;
}

static size_t lua_packet_end(lua_Integer position, size_t length) {
    if (position > (lua_Integer)length) {
        return length;
    }
    if (position >= 0) {
        return (size_t)position;
    }
    if (position < -(lua_Integer)length) {
        return 0;
    }
    return length + (size_t)position + 1;
}

static int lua_packet_copy(size_t offset, unsigned char* destination, size_t length) {
    size_t packet_length = lua_current_state()->packet_size;
    if (offset > packet_length || length > packet_length - offset) {
        return -1;
    }
    for (size_t index = 0; index < length; ++index) {
        struct xdp_md* ctx = capsule_borrowed_ctx();
        unsigned char* data = (unsigned char*)(long)ctx->data;
        unsigned char* data_end = (unsigned char*)(long)ctx->data_end;
        size_t at = offset + index;
        asm volatile("" : "+r"(at));
        at &= LUA_XDP_PACKET_CAPACITY - 1u;
        if (data + at + 1 > data_end) {
            return -1;
        }
        destination[index] = data[at];
    }
    return 0;
}

static int lua_packet_len(lua_State* state) {
    (void)luaL_checkudata(state, 1, LUA_PACKET_METATABLE);
    lua_pushinteger(state, (lua_Integer)lua_current_state()->packet_size);
    return 1;
}

static int lua_packet_byte(lua_State* state) {
    (void)luaL_checkudata(state, 1, LUA_PACKET_METATABLE);
    size_t length = lua_current_state()->packet_size;
    lua_Integer first_argument = luaL_optinteger(state, 2, 1);
    size_t first = lua_packet_start(first_argument, length);
    size_t last = lua_packet_end(luaL_optinteger(state, 3, first_argument), length);
    if (first > last) {
        return 0;
    }
    size_t count = last - first + 1;
    luaL_checkstack(state, (int)count, "packet slice too long");
    for (size_t index = 0; index < count; ++index) {
        unsigned char byte = 0;
        if (lua_packet_copy(first - 1 + index, &byte, 1)) {
            return luaL_error(state, "packet changed during inspection");
        }
        lua_pushinteger(state, byte);
    }
    return (int)count;
}

static int lua_packet_sub(lua_State* state) {
    (void)luaL_checkudata(state, 1, LUA_PACKET_METATABLE);
    size_t length = lua_current_state()->packet_size;
    size_t first = lua_packet_start(luaL_checkinteger(state, 2), length);
    size_t last = lua_packet_end(luaL_optinteger(state, 3, -1), length);
    size_t count = first <= last ? last - first + 1 : 0;
    luaL_Buffer buffer;
    unsigned char* result = (unsigned char*)luaL_buffinitsize(state, &buffer, count);
    if (count && lua_packet_copy(first - 1, result, count)) {
        return luaL_error(state, "packet changed during inspection");
    }
    luaL_pushresultsize(&buffer, count);
    return 1;
}

static void lua_open_packet(lua_State* state) {
    if (luaL_newmetatable(state, LUA_PACKET_METATABLE)) {
        lua_pushcfunction(state, lua_packet_len);
        lua_setfield(state, -2, "__len");
        lua_pushcfunction(state, lua_packet_byte);
        lua_setfield(state, -2, "byte");
        lua_pushcfunction(state, lua_packet_sub);
        lua_setfield(state, -2, "sub");
        lua_pushvalue(state, -1);
        lua_setfield(state, -2, "__index");
    }
    lua_pop(state, 1);
    (void)lua_newuserdatauv(state, 0, 0);
    luaL_setmetatable(state, LUA_PACKET_METATABLE);
    lua_setglobal(state, "packet");
}

static void lua_initialize_state(struct lua_fiber_state* fiber) {
    fiber->state = luaL_newstate();
    if (!fiber->state) {
        capsule_exit(1);
    }
    luaL_openlibs(fiber->state);
    lua_open_packet(fiber->state);
    int status = luaL_loadbuffer(fiber->state, lua_xdp_control.script, (unsigned long)lua_xdp_control.script_size, "xdp.lua");
    if (status) {
        lua_report_error(fiber->state);
        capsule_exit(1);
    }
    fiber->script_reference = luaL_ref(fiber->state, LUA_REGISTRYINDEX);
}

void lua_initialize_states(void) {
    if (!lua_xdp_control.script || !lua_xdp_control.script_size) {
        capsule_exit(1);
    }
    unsigned int count = capsule_fiber_count();
    for (unsigned int fiber_index = 0; fiber_index < count; ++fiber_index) {
        lua_initialize_state(&lua_states[fiber_index]);
    }
}

size_t lua_xdp_execute(size_t packet_size) {
    struct lua_fiber_state* fiber = lua_current_state();
    fiber->packet_size = packet_size;
    fiber->output_size = 0;
    lua_State* state = fiber->state;
    lua_settop(state, 0);
    lua_rawgeti(state, LUA_REGISTRYINDEX, fiber->script_reference);
    int status = lua_pcall(state, 0, 0, 0);
    if (status) {
        lua_report_error(state);
        capsule_exit(1);
    }
    return fiber->output_size;
}
