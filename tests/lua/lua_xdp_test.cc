// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "lua_xdp_ctrl.h"
#include "lua_xdp_test_guest.skel.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <pthread.h>
#include <sched.h>

namespace {

constexpr size_t SamplePacketBytes = 54;
constexpr char SampleOutput[] = "TCP 192.0.2.1:51515 > 198.51.100.2:443\n";
const std::array<unsigned char, SamplePacketBytes> samplePacket = {
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x08,
    0x00,
    0x45,
    0x00,
    0x00,
    0x28,
    0x12,
    0x34,
    0x40,
    0x00,
    0x40,
    0x06,
    0x00,
    0x00,
    0xc0,
    0x00,
    0x02,
    0x01,
    0xc6,
    0x33,
    0x64,
    0x02,
    0xc9,
    0x3b,
    0x01,
    0xbb,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xfa,
    0xf0,
    0x00,
    0x00,
    0x00,
    0x00,
};

std::filesystem::path fixturePath(const char* environment, const char* source, const char* installed) {
    if (const char* configured = std::getenv(environment); configured && *configured) {
        return configured;
    }
    if (std::filesystem::is_regular_file(source)) {
        return source;
    }
    std::error_code error;
    std::filesystem::path executable = std::filesystem::read_symlink("/proc/self/exe", error);
    return error ? source : executable.parent_path() / installed;
}

int pinCurrentThread(unsigned int cpu) {
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    int error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    if (error) {
        errno = error;
        return -1;
    }
    return 0;
}

int firstAllowedCpu(const cpu_set_t& allowed) {
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &allowed)) {
            return cpu;
        }
    }
    errno = ENODEV;
    return -1;
}

int collectEvent(void* context, void* data, size_t size) {
    auto* events = static_cast<std::vector<std::string>*>(context);
    events->emplace_back(static_cast<const char*>(data), size);
    return 0;
}

class LuaXdpTest : public ::testing::Test {
protected:
    void SetUp() override {
        CAPSULE_REQUIRE_BPF_PRIVILEGE();
        skeleton_ = lua_xdp_test_guest__open();
        ASSERT_NE(skeleton_, nullptr);

        ASSERT_EQ(sched_getaffinity(0, sizeof(allowedCpus_), &allowedCpus_), 0) << strerror(errno);
        int selected = firstAllowedCpu(allowedCpus_);
        ASSERT_GE(selected, 0);
        cpu_ = (unsigned int)selected;
        haveAffinity_ = true;
    }

    void TearDown() override {
        if (haveAffinity_) {
            (void)sched_setaffinity(0, sizeof(allowedCpus_), &allowedCpus_);
        }
        ring_buffer__free(ring_);
        (void)bpf_capsule_release(&capsule_);
        lua_xdp_test_guest__destroy(skeleton_);
    }

    int initializeStates() {
        struct bpf_program* initialize = bpf_object__find_program_by_name(skeleton_->obj, "lua_xdp_initialize");
        struct bpf_program* drain = bpf_object__find_program_by_name(skeleton_->obj, "lua_xdp_initialize_drain");
        if (!initialize || !drain) {
            errno = ENOENT;
            return -1;
        }
        struct bpf_test_run_opts options = {};
        options.sz = sizeof(options);
        if (capsule_test_drive(bpf_program__fd(initialize), bpf_program__fd(drain), &options, 2000000, nullptr, nullptr, &control_->initialization)) {
            return -1;
        }
        if (control_->initialization.status != CAPSULE_OK) {
            errno = ECANCELED;
            return -1;
        }
        return 0;
    }

    int startSource(const std::string& source) {
        if (source.empty()) {
            errno = EINVAL;
            return -1;
        }
        int cpuCount = libbpf_num_possible_cpus();
        if (cpuCount < 1) {
            errno = cpuCount < 0 ? -cpuCount : EINVAL;
            return -1;
        }
        struct bpf_capsule_config config = {};
        config.fiber_count = (unsigned int)cpuCount;
        config.heap_bytes = (4ull << 20) + (uint64_t)cpuCount * (256ull << 10);
        config.reserved_bytes = source.size();
        if (bpf_capsule_configure(&capsule_, skeleton_->obj, config) || bpf_object__load_skeleton(skeleton_->skeleton) || bpf_capsule_initialize(&capsule_)) {
            return -1;
        }
        control_ = &skeleton_->data_lua_xdp->lua_xdp_control;
        program_ = bpf_object__find_program_by_name(skeleton_->obj, "lua_xdp_observe");
        struct bpf_map* events = bpf_object__find_map_by_name(skeleton_->obj, "lua_xdp_events");
        if (!program_ || !events) {
            errno = ENOENT;
            return -1;
        }
        ring_ = ring_buffer__new(bpf_map__fd(events), collectEvent, &events_, nullptr);
        if (!ring_) {
            return -1;
        }
        long ringError = libbpf_get_error(ring_);
        if (ringError) {
            ring_ = nullptr;
            errno = (int)-ringError;
            return -1;
        }
        control_->script = static_cast<char*>(bpf_capsule_memory_reserved_start(&capsule_));
        if (bpf_capsule_memcpy(&capsule_, control_->script, source.data(), source.size())) {
            return -1;
        }
        control_->script_size = source.size();
        if (pinCurrentThread(cpu_)) {
            return -1;
        }
        return initializeStates();
    }

    int startFile(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            errno = ENOENT;
            return -1;
        }
        std::string source((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return startSource(source);
    }

    bool runPacket(const void* packet, size_t length) {
        std::array<unsigned char, LUA_XDP_PACKET_CAPACITY + 1> output = {};
        struct bpf_test_run_opts options = {};
        options.sz = sizeof(options);
        options.data_in = packet;
        options.data_size_in = length;
        options.data_out = output.data();
        options.data_size_out = output.size();
        options.repeat = 1;
        if (pinCurrentThread(cpu_) || bpf_prog_test_run_opts(bpf_program__fd(program_), &options)) {
            return false;
        }
        return options.retval == XDP_PASS;
    }

    bool runObserverPacket(const void* packet, size_t length, const char* expected) {
        if (!clearEvents() || !runPacket(packet, length) || !pollEvents()) {
            return false;
        }
        return events_.size() == 1 && events_[0] == expected;
    }

    bool runErrorPacket(const char* expected) {
        if (!clearEvents() || !runPacket(samplePacket.data(), samplePacket.size()) || !pollEvents()) {
            return false;
        }
        const std::string text = events_.size() == 1 ? events_[0] : std::string();
        return events_.size() == 1 && text.find(expected) != std::string::npos;
    }

    bool pollEvents() {
        int result;
        do {
            result = ring_buffer__poll(ring_, 0);
        } while (result > 0);
        return result >= 0;
    }

    bool clearEvents() {
        if (!ring_ || !pollEvents()) {
            return false;
        }
        events_.clear();
        return true;
    }

    bool runConcurrentPackets() {
        if (!clearEvents()) {
            return false;
        }
        (void)sched_setaffinity(0, sizeof(allowedCpus_), &allowedCpus_);
        struct Worker {
            unsigned int cpu;
            bool failed = false;
        };
        std::vector<Worker> workers;
        workers.reserve(8);
        for (int cpu = 0; cpu < CPU_SETSIZE && workers.size() < 8; ++cpu) {
            if (!CPU_ISSET(cpu, &allowedCpus_)) {
                continue;
            }
            workers.push_back({(unsigned int)cpu});
        }
        if (workers.size() < 2) {
            return true;
        }

        std::mutex mutex;
        std::condition_variable condition;
        bool started = false;
        std::vector<std::thread> threads;
        threads.reserve(workers.size());
        for (Worker& worker : workers) {
            threads.emplace_back([&, workerPtr = &worker] {
                if (pinCurrentThread(workerPtr->cpu)) {
                    workerPtr->failed = true;
                    return;
                }
                {
                    std::unique_lock lock(mutex);
                    condition.wait(lock, [&] { return started; });
                }
                for (unsigned int iteration = 0; iteration < 32; ++iteration) {
                    std::array<unsigned char, SamplePacketBytes> output = {};
                    struct bpf_test_run_opts options = {};
                    options.sz = sizeof(options);
                    options.data_in = samplePacket.data();
                    options.data_size_in = samplePacket.size();
                    options.data_out = output.data();
                    options.data_size_out = output.size();
                    if (bpf_prog_test_run_opts(bpf_program__fd(program_), &options) || options.retval != XDP_PASS) {
                        workerPtr->failed = true;
                    }
                }
            });
        }
        {
            std::lock_guard lock(mutex);
            started = true;
        }
        condition.notify_all();
        for (std::thread& thread : threads) {
            thread.join();
        }
        if (!pollEvents()) {
            return false;
        }
        size_t expectedEvents = workers.size() * 32;
        return events_.size() == expectedEvents &&
            std::all_of(events_.begin(), events_.end(), [](const std::string& event) { return event == SampleOutput; }) &&
            std::none_of(workers.begin(), workers.end(), [](const Worker& worker) { return worker.failed; });
    }

    struct lua_xdp_test_guest* skeleton_ = nullptr;
    struct bpf_capsule capsule_ = {};
    volatile struct lua_xdp_ctrl* control_ = nullptr;
    struct bpf_program* program_ = nullptr;
    struct ring_buffer* ring_ = nullptr;
    std::vector<std::string> events_;
    cpu_set_t allowedCpus_ = {};
    unsigned int cpu_ = 0;
    bool haveAffinity_ = false;
};

TEST_F(LuaXdpTest, ObserverPacketsAndConcurrency) {
    std::filesystem::path observer = fixturePath("BPF_CAPSULE_LUA_XDP_OBSERVER", LUA_XDP_OBSERVER, "lua-xdp-observer.lua");
    ASSERT_EQ(startFile(observer), 0) << "cannot start " << observer << ": " << strerror(errno);
    EXPECT_TRUE(runConcurrentPackets());
    std::array<unsigned char, 42> udpPacket = {};
    std::copy_n(samplePacket.begin(), udpPacket.size(), udpPacket.begin());
    udpPacket[16] = 0;
    udpPacket[17] = 0x1c;
    udpPacket[23] = 17;
    udpPacket[34] = 0x14;
    udpPacket[35] = 0xe9;
    udpPacket[36] = 0;
    udpPacket[37] = 0x35;
    std::array<unsigned char, 34> ipPacket = {};
    std::copy_n(samplePacket.begin(), ipPacket.size(), ipPacket.begin());
    ipPacket[16] = 0;
    ipPacket[17] = 0x14;
    ipPacket[23] = 1;
    std::array<unsigned char, LUA_XDP_PACKET_CAPACITY + 1> prefixPacket = {};
    std::copy_n(samplePacket.begin(), 12, prefixPacket.begin());
    prefixPacket[12] = 0x86;
    prefixPacket[13] = 0xdd;

    EXPECT_TRUE(runObserverPacket(samplePacket.data(), samplePacket.size(), SampleOutput));
    EXPECT_TRUE(runObserverPacket(udpPacket.data(), udpPacket.size(), "UDP 192.0.2.1:5353 > 198.51.100.2:53\n"));
    EXPECT_TRUE(runObserverPacket(ipPacket.data(), ipPacket.size(), "IP 192.0.2.1 > 198.51.100.2 proto=1\n"));
    EXPECT_TRUE(runObserverPacket(samplePacket.data(), 14, "TRUNC ipv4 len=14\n"));
    EXPECT_TRUE(runObserverPacket(prefixPacket.data(), prefixPacket.size(), "ETH type=0x86dd len=2048\n"));
}

TEST_F(LuaXdpTest, RuntimeErrorsStayContained) {
    ASSERT_EQ(startSource("error(\"expected Lua XDP error\")\n"), 0);
    EXPECT_TRUE(runErrorPacket("expected Lua XDP error"));
    EXPECT_TRUE(runErrorPacket("expected Lua XDP error"));
}

TEST_F(LuaXdpTest, SyntaxErrorFailsInitialization) {
    EXPECT_NE(startSource("local =\n"), 0);
    ASSERT_NE(control_, nullptr);
    EXPECT_EQ(control_->initialization.status, (unsigned int)CAPSULE_EXITED);
    EXPECT_EQ(control_->initialization.code, 1);
}

} // namespace
