// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Per-fiber stock-Lua state and the borrowed XDP packet API.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdlib.h>

#include "bpf_capsule.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lua_capsule_runtime.h"
#include "lua_xdp_internal.h"

struct lua_fiber_state {
    lua_State* state;
    uint64_t script_revision;
    uint64_t packet_size;
    uint64_t output_size;
    uint64_t error_size;
    uint64_t initializations;
    int policy_reference;
    unsigned int poisoned;
};

// The default 512-fiber cap costs one 4 KiB pointer table. Lua states and
// their allocations exist only for the load-time-active fiber count.
static struct lua_fiber_state* lua_states[BPF_CAPSULE_MAX_FIBERS];

static struct lua_fiber_state* lua_current_state(void) {
    unsigned int fiber = capsule_fiber_index();
    if (fiber >= BPF_CAPSULE_MAX_FIBERS) {
        capsule_exit(1);
    }
    return lua_states[fiber];
}

static void lua_exchange_write(int error, uint64_t* size, const char* text, unsigned long length) {
    uint64_t begin = *size;
    *size += length;
    if (error) {
        struct lua_exchange* sizes = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
        if (!sizes) {
            capsule_exit(1);
        }
        sizes->error_size = *size;
    }
    uint64_t available = begin < LUA_XDP_OUTPUT_CAPACITY ? LUA_XDP_OUTPUT_CAPACITY - begin : 0;
    unsigned long copied = length < available ? length : (unsigned long)available;
    for (unsigned long index = 0; index < copied; ++index) {
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
        // its unbounded components after a resumable-loop frame reload.
        asm volatile("" : "+r"(at));
        at &= LUA_XDP_OUTPUT_CAPACITY - 1u;
        unsigned long buffer_offset = error ? LUA_XDP_OUTPUT_CAPACITY : 0;
        asm volatile("" : "+r"(buffer_offset));
        buffer_offset &= LUA_XDP_OUTPUT_CAPACITY;
        ((char*)exchange)[buffer_offset + at] = byte;
    }
}

void lua_capsule_write(const char* text, unsigned long length) {
    struct lua_fiber_state* fiber = lua_current_state();
    if (!fiber) {
        capsule_exit(1);
    }
    lua_exchange_write(0, &fiber->output_size, text, length);
}

void lua_capsule_error(lua_State* state, int status, const char* message, unsigned long length) {
    (void)status;
    struct lua_fiber_state* fiber = lua_capsule_owner(state);
    if (fiber) {
        fiber->poisoned = 1;
        lua_exchange_write(1, &fiber->error_size, message, length);
    }
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

static size_t lua_packet_length(void) {
    struct lua_fiber_state* fiber = lua_current_state();
    return fiber ? (size_t)fiber->packet_size : 0;
}

static int lua_packet_copy(size_t offset, unsigned char* destination, size_t length) {
    size_t packet_length = lua_packet_length();
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

static void lua_packet_check(lua_State* state) {
    (void)luaL_checkudata(state, 1, LUA_PACKET_METATABLE);
}

static int lua_packet_len(lua_State* state) {
    lua_packet_check(state);
    lua_pushinteger(state, (lua_Integer)lua_packet_length());
    return 1;
}

static int lua_packet_byte(lua_State* state) {
    lua_packet_check(state);
    size_t length = lua_packet_length();
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
    lua_packet_check(state);
    size_t length = lua_packet_length();
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

static int lua_initialize_state(struct lua_fiber_state* fiber, uint64_t revision) {
    if (!lua_xdp_control.script_address || !lua_xdp_control.script_size || lua_xdp_control.script_size >= LUA_XDP_SCRIPT_CAPACITY) {
        return -1;
    }
    if (fiber->state && !fiber->poisoned && fiber->script_revision == revision) {
        return 0;
    }
    if (fiber->state) {
        if (!fiber->poisoned) {
            lua_close(fiber->state);
        }
        // A terminating Lua throw can leave internal lists half-mutated.
        // Never traverse that VM again, even to close it; a later script
        // reload replaces it with a fresh state from the Capsule heap.
        fiber->state = NULL;
    }

    fiber->state = lua_capsule_newstate(fiber);
    fiber->poisoned = 0;
    fiber->policy_reference = LUA_NOREF;
    if (!fiber->state) {
        return -1;
    }
    luaL_openlibs(fiber->state);
    lua_open_packet(fiber->state);
    const char* source = (const char*)(unsigned long)lua_xdp_control.script_address;
    // A parse/allocation error takes Capsule's terminating Lua throw path and
    // marks this state poisoned; it cannot return a recoverable Lua status.
    (void)luaL_loadbuffer(fiber->state, source, (unsigned long)lua_xdp_control.script_size, "xdp.lua");
    fiber->policy_reference = luaL_ref(fiber->state, LUA_REGISTRYINDEX);
    fiber->script_revision = revision;
    ++fiber->initializations;
    return 0;
}

void lua_initialize_states(void) {
    unsigned int count = capsule_fiber_count();
    uint64_t revision = lua_xdp_control.script_revision + 1;
    if (!revision) {
        capsule_exit(1);
    }
    for (unsigned int fiber_index = 0; fiber_index < count; ++fiber_index) {
        struct lua_fiber_state* fiber = lua_states[fiber_index];
        if (!fiber) {
            fiber = calloc(1, sizeof(*fiber));
            if (!fiber) {
                capsule_exit(1);
            }
            lua_states[fiber_index] = fiber;
        }
        if (lua_initialize_state(fiber, revision)) {
            capsule_exit(1);
        }
    }
    // Publish the revision only after every fiber owns a ready VM. If an
    // earlier fiber throws, initialization terminates as CAPSULE_EXITED with
    // a negative code and packet entries reject the entire partially rebuilt
    // generation.
    lua_xdp_control.script_revision = revision;
}

static void lua_reset_exchange(struct lua_fiber_state* fiber) {
    fiber->output_size = 0;
    fiber->error_size = 0;
    struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
    if (!exchange) {
        capsule_exit(1);
    }
    exchange->output.bytes[0] = 0;
    exchange->error.bytes[0] = 0;
    exchange->error_size = 0;
}

static void lua_terminate_exchange(struct lua_fiber_state* fiber) {
    struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
    if (!exchange) {
        capsule_exit(1);
    }
    if (fiber->output_size < LUA_XDP_OUTPUT_CAPACITY) {
        exchange->output.bytes[fiber->output_size] = 0;
    }
    if (fiber->error_size < LUA_XDP_OUTPUT_CAPACITY) {
        exchange->error.bytes[fiber->error_size] = 0;
    }
}

static struct lua_xdp_result lua_run_body(void) {
    struct lua_xdp_result result = {0};
    struct lua_fiber_state* fiber = lua_current_state();
    if (!fiber || !fiber->state) {
        capsule_exit(1);
    }
    if (lua_xdp_control.initialization.status != CAPSULE_OK || fiber->poisoned || fiber->script_revision != lua_xdp_control.script_revision) {
        static const char message[] = "Lua state is unavailable; reload the script";
        lua_reset_exchange(fiber);
        lua_exchange_write(1, &fiber->error_size, message, sizeof(message) - 1);
        lua_terminate_exchange(fiber);
        capsule_exit(1);
    }
    lua_reset_exchange(fiber);
    lua_State* state = fiber->state;
    lua_settop(state, 0);
    lua_rawgeti(state, LUA_REGISTRYINDEX, fiber->policy_reference);
    // Lua errors abort the Capsule call and are copied to exchange->error;
    // only a successful protected call can return here.
    (void)lua_pcall(state, 0, 1, 0);
    result.decision = (uint64_t)(int64_t)lua_tointeger(state, -1);
    lua_pop(state, 1);
    lua_terminate_exchange(fiber);
    result.output_size = fiber->output_size;
    result.state_initializations = fiber->initializations;
    return result;
}

struct lua_xdp_result lua_xdp_execute(unsigned long packet_size) {
    struct lua_fiber_state* fiber = lua_current_state();
    if (!fiber) {
        capsule_exit(1);
    }
    fiber->packet_size = packet_size;
    return lua_run_body();
}
