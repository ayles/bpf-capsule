// SPDX-License-Identifier: GPL-2.0-only
// DOOM's kernel side: the entry points userspace invokes, and the handful of
// callbacks the engine needs from its host. Everything that makes ordinary C
// runnable in the kernel lives in the runtime header and the passes, not here.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "bpf_ctrl.h"
#include <stdlib.h>

// PureDOOM's single-header platform API is the entire BPF porting boundary.
// The build applies two non-BPF, allocator-independent rendering fixes to its
// private PureDOOM copy; see the example README.
#define DOOM_IMPLEMENTATION
#include "PureDOOM.h"

char _license[] SEC("license") = "GPL";

// The one page userspace and the kernel both reach directly. Everything else
// lives in the relocated address space and is reached by the address reported
// here.
volatile struct doom_bpf_ctrl ctrl SEC(".data.ctrl");

// Sized for Freedoom Phase 1 (~28 MiB), the free IWAD the tooling fetches
// by default; the shareware doom1.wad (4 MiB) fits trivially. This is ordinary
// unsectioned program storage: Capsule chooses its kernel representation and
// keeps the zero-filled buffer out of the object image.
#define WAD_CAPACITY (30 << 20)
unsigned char wad_buf[WAD_CAPACITY];

// Sectioned because userspace reads this map directly. Rounded up to a power
// of two so the verifier-visible mask survives stackification.
#define FRAME_BYTES (320 * 200 * 4)
#define FRAME_SIZE (1 << 18)
unsigned char doom_fb[FRAME_SIZE] SEC(".bss.fb");

static void copy_frame(const unsigned char* frame) {
    for (unsigned long i = 0; i < FRAME_BYTES; i += 8) {
        unsigned long j = i;
        asm volatile("" : "+r"(j));
        *(uint64_t*)(doom_fb + (j & (FRAME_SIZE - 8))) = *(const uint64_t*)(frame + i);
    }
}

// ------------------------------------------------------------- callbacks

struct wad_file {
    unsigned long size;
    unsigned long position;
};

static struct wad_file wad_file;
static uint64_t frame_clock;

static const char* basename(const char* path) {
    const char* name = path;
    for (; *path; path++) {
        if (*path == '/' || *path == '\\') {
            name = path + 1;
        }
    }
    return name;
}

static void* platform_malloc(int size) {
    if (size <= 0) {
        return 0;
    }
    void* result = malloc((unsigned long)size);
    if (!result) {
        capsule_exit(1);
    }
    return result;
}

static void platform_free(void* pointer) {
    free(pointer);
}

static void* platform_open(const char* path, const char* mode) {
    if (!mode || mode[0] != 'r' || doom_strcmp(basename(path), "doom1.wad")) {
        return 0;
    }
    wad_file.position = 0;
    return &wad_file;
}

static void platform_close(void* handle) {
    (void)handle;
}

static int platform_read(void* handle, void* destination, int count) {
    if (handle != &wad_file || count <= 0) {
        return count == 0 ? 0 : -1;
    }
    unsigned long left = wad_file.size - wad_file.position;
    unsigned long length = (unsigned long)count;
    if (length > left) {
        length = left;
    }
    unsigned char* output = destination;
    for (unsigned long i = 0; i < length; i++) {
        output[i] = wad_buf[wad_file.position + i];
    }
    wad_file.position += length;
    return (int)length;
}

static int platform_write(void* handle, const void* source, int count) {
    (void)handle;
    (void)source;
    (void)count;
    return -1;
}

static int platform_seek(void* handle, int offset, doom_seek_t origin) {
    if (handle != &wad_file) {
        return -1;
    }
    long base = 0;
    if (origin == DOOM_SEEK_CUR) {
        base = (long)wad_file.position;
    } else if (origin == DOOM_SEEK_END) {
        base = (long)wad_file.size;
    } else if (origin != DOOM_SEEK_SET) {
        return -1;
    }
    long position = base + offset;
    if (position < 0 || (unsigned long)position > wad_file.size) {
        return -1;
    }
    wad_file.position = (unsigned long)position;
    return 0;
}

static int platform_tell(void* handle) {
    return handle == &wad_file ? (int)wad_file.position : -1;
}

static int platform_eof(void* handle) {
    return handle != &wad_file || wad_file.position >= wad_file.size;
}

static void platform_gettime(int* seconds, int* microseconds) {
    *seconds = (int)(frame_clock / 35);
    *microseconds = (int)(frame_clock % 35) * 1000000 / 35;
}

static char* platform_getenv(const char* name) {
    return doom_strcmp(name, "HOME") == 0 ? "." : 0;
}

static void platform_exit(int code) {
    capsule_exit(code);
}

static void platform_print(const char* text) {
    long len = doom_strlen(text);
    // PureDOOM reports fatal errors through its print callback immediately
    // before doom_exit(). Preserve that message in the mmaped control map so
    // the host can explain the abort.
    if (!ctrl.error_len && len >= 6 && text[0] == 'E' && text[1] == 'r' && text[2] == 'r' && text[3] == 'o' && text[4] == 'r' && text[5] == ':') {
        unsigned int copy = len < sizeof(ctrl.error_text) - 1 ? (unsigned int)len : (unsigned int)sizeof(ctrl.error_text) - 1;
        for (unsigned int i = 0; i < copy; ++i) {
            ctrl.error_text[i] = text[i];
        }
        ctrl.error_text[copy] = 0;
        ctrl.error_len = copy;
    }
}

// ------------------------------------------------------------ entry points

static void doom_prepare_body(void) {
    ctrl.wad_addr = (uint64_t)(void*)wad_buf;
    ctrl.wad_capacity = sizeof(wad_buf);
}

SEC("syscall")
int doom_prepare() {
    ctrl.capsule = capsule_call_void(doom_prepare_body);
    return 0;
}

// Engine start-up as its own managed body: WAD parsing, zone setup and the
// initial level load are far heavier than any frame, so they run once behind
// their own entry instead of hiding inside the first frame.
static void doom_start_body(void) {
    wad_file.size = ctrl.wad_size;
    doom_set_print(platform_print);
    doom_set_malloc(platform_malloc, platform_free);
    doom_set_file_io(platform_open, platform_close, platform_read, platform_write, platform_seek, platform_tell, platform_eof);
    doom_set_gettime(platform_gettime);
    doom_set_exit(platform_exit);
    doom_set_getenv(platform_getenv);

    char* normal_argv[] = {"bpf-doom"};
    char* autostart_argv[] = {"bpf-doom", "-warp", "1", "1"};
    doom_init(
        ctrl.autostart ? 4 : 1, ctrl.autostart ? autostart_argv : normal_argv,
        DOOM_FLAG_HIDE_MOUSE_OPTIONS | DOOM_FLAG_HIDE_SOUND_OPTIONS | DOOM_FLAG_HIDE_MUSIC_OPTIONS
    );
    ctrl.inited = 1;
}

SEC("syscall")
int doom_start() {
    ctrl.capsule = capsule_call_void(doom_start_body);
    return 0;
}

// One frame: advance the game and render it. The whole frame is one managed
// body: every piece must run in order on the software stack, and only ctrl
// bookkeeping stays in the entry. The engine must already be started; a frame
// never initializes.
static void doom_frame_body(void) {
    if (!ctrl.inited) {
        capsule_exit(1);
    }
    unsigned input_count = ctrl.input_count;
    if (input_count > DOOM_INPUT_QUEUE_CAPACITY) {
        input_count = DOOM_INPUT_QUEUE_CAPACITY;
    }
    for (unsigned i = 0; i < input_count; i++) {
        unsigned event = ctrl.input_events[i & (DOOM_INPUT_QUEUE_CAPACITY - 1)];
        int key = (int)(event & DOOM_INPUT_KEY_MASK);
        if (event & DOOM_INPUT_DOWN) {
            doom_key_down(key);
        } else {
            doom_key_up(key);
        }
    }
    ctrl.input_count = 0;
    doom_force_update();
    frame_clock++;

    if (ctrl.want_frame) {
        copy_frame(doom_get_framebuffer(4));
    }
}

SEC("syscall")
int doom_frame() {
    ctrl.capsule = capsule_call_void(doom_frame_body);
    return 0;
}
