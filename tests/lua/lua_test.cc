// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The full Lua interpreter as a correctness test: publish guest buffers,
// stage a script through Capsule memory, run it in the kernel, and compare
// the exact stdout the script must produce. The expected text is computed by
// the script's own arithmetic: sum((1..2000)*17) mod 1000003 = 16898, io.read
// on empty batch stdin yields nil, io.read("a") yields "", and decimal plus
// hexadecimal floating-point literals exercise the freestanding strtod path.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "lua_runner_ctrl.h"
#include "lua_runner.skel.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

std::filesystem::path scriptPath() {
    if (const char* configured = std::getenv("BPF_CAPSULE_LUA_SCRIPT"); configured && *configured) {
        return configured;
    }
    std::filesystem::path source = LUA_TEST_SCRIPT;
    if (std::filesystem::is_regular_file(source)) {
        return source;
    }
    std::error_code error;
    std::filesystem::path executable = std::filesystem::read_symlink("/proc/self/exe", error);
    return error ? source : executable.parent_path() / "script.lua";
}

class LuaTest : public ::testing::Test {
protected:
    void SetUp() override {
        CAPSULE_REQUIRE_BPF_PRIVILEGE();
        skeleton_ = lua_runner__open();
        ASSERT_NE(skeleton_, nullptr);
        struct bpf_capsule_config config = {};
        config.fiber_count = 1;
        config.heap_bytes = 16ull << 20;
        ASSERT_EQ(bpf_capsule_configure(&capsule_, skeleton_->obj, config), 0) << strerror(errno);
        ASSERT_EQ(lua_runner__load(skeleton_), 0) << strerror(errno);
        ASSERT_EQ(bpf_capsule_initialize(&capsule_), 0) << strerror(errno);
        control_ = &skeleton_->data_lua_runner->lua_runner_control;
    }

    void TearDown() override {
        (void)bpf_capsule_release(&capsule_);
        lua_runner__destroy(skeleton_);
    }

    // The stock test workloads are expected to fit one drive span. Examples
    // expose an explicit opt-in for larger user scripts; this test fails if a
    // dependency or compiler change silently starts requiring continuations.
    void Drive(const char* entry) {
        ASSERT_EQ(capsule_test_run_program(skeleton_->obj, entry), 0) << entry << ": " << strerror(errno);
        ASSERT_NE(control_->capsule.status, (unsigned)CAPSULE_PENDING) << entry << " unexpectedly requires a continuation drain";
    }

    void RunScript(const std::string& script) {
        Drive("lua_prepare");
        ASSERT_EQ(control_->capsule.status, (unsigned)CAPSULE_OK) << "buffer publication failed, code " << control_->capsule.code;
        ASSERT_LE(script.size(), control_->script.capacity);
        ASSERT_EQ(bpf_capsule_memcpy(&capsule_, control_->script.address, script.data(), script.size()), 0) << strerror(errno);
        control_->script.size = script.size();
        control_->input.size = 0;
        Drive("lua_run");
    }

    std::string Output() {
        EXPECT_LE(control_->output.size, control_->output.capacity) << "guest stdout truncated";
        std::string output(control_->output.size, '\0');
        if (!output.empty()) {
            memcpy(output.data(), control_->output.address, output.size());
        }
        return output;
    }

    std::string ErrorText() {
        size_t size = control_->error.size < control_->error.capacity ? control_->error.size : control_->error.capacity;
        std::string text(size, '\0');
        if (size) {
            memcpy(text.data(), control_->error.address, size);
        }
        return text;
    }

    struct lua_runner* skeleton_ = nullptr;
    struct bpf_capsule capsule_ = {};
    volatile struct lua_runner_ctrl* control_ = nullptr;
};

TEST_F(LuaTest, ScriptChecksumAndBatchStdin) {
    std::filesystem::path path = scriptPath();
    std::ifstream file(path);
    ASSERT_TRUE(file) << "missing " << path;
    std::string script((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    ASSERT_FALSE(script.empty());

    RunScript(script);
    ASSERT_EQ(control_->capsule.status, (unsigned)CAPSULE_OK)
        << "status " << control_->capsule.status << " code " << control_->capsule.code << "; guest error: " << ErrorText();
    EXPECT_EQ(Output(), "Lua checksum\t16898\ttrue\t0\ttrue\n");
}

TEST_F(LuaTest, ProtectedCallRecovers) {
    RunScript("local ok, message = pcall(function() error('caught failure') end)\n"
              "print(ok, message:find('caught failure', 1, true) ~= nil)\n");
    ASSERT_EQ(control_->capsule.status, (unsigned)CAPSULE_OK)
        << "status " << control_->capsule.status << " code " << control_->capsule.code << "; guest error: " << ErrorText();
    EXPECT_EQ(Output(), "false\ttrue\n");
    EXPECT_TRUE(ErrorText().empty());
}

TEST_F(LuaTest, ScriptErrorReportsGuestExit) {
    RunScript("error('deliberate failure')");
    // The Capsule Lua adapter exits 1 on a script error and records the Lua
    // message in the error buffer.
    ASSERT_EQ(control_->capsule.status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(control_->capsule.code, 1);
    EXPECT_NE(ErrorText().find("deliberate failure"), std::string::npos) << "error text: " << ErrorText();
}

} // namespace
