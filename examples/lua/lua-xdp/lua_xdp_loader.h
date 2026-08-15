// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <bpf/libbpf.h>

// Configure one active fiber per possible CPU before load. After load,
// lua_xdp_load_script stages the source in unified memory and constructs one
// ready Lua VM for every configured fiber; the caller passes its typed
// control pointer (skeleton->data_lua_xdp->lua_xdp_control). Loading is a
// quiescent control-plane operation: do not run an XDP entry concurrently
// with a script reload.
struct lua_xdp_ctrl;
int lua_xdp_configure(struct bpf_object* object);
int lua_xdp_load_script(struct bpf_object* object, volatile struct lua_xdp_ctrl* control, const char* path);
