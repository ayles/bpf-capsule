// SPDX-License-Identifier: GPL-2.0-only
// The entire host side. DOOM runs in the kernel; this loads it, feeds it
// input, and shows what it drew. It knows nothing about the memory backend,
// the call stack or the verifier: small shared values use explicit control
// maps, while the WAD goes through Capsule's backend-neutral memory API.
// With --native the same engine steps run in this process instead, so the
// two builds can be compared frame for frame.
//
//   doom [--native] WAD tty          stdin keys in, truecolor terminal out
//   doom [--native] WAD dump N DIR   N deterministic frames to DIR as PPM
#include "bpf_ctrl.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "doom.skel.h"

// The native engine returns from doom_exit() through this point.
static jmp_buf native_exit_point;
static void native_exit(int code) {
    longjmp(native_exit_point, code + 1);
}

#define DOOM_ENGINE_EXIT(code) native_exit(code)
#define DOOM_ENGINE_ERROR(text, length) fprintf(stderr, "%.*s\n", (int)(length), (text))
#include "doom_engine.h"

#define W 320
#define H 200

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static void print_capsule_error_text(volatile const struct doom_bpf_ctrl* control) {
    if (!control->error_len) {
        return;
    }
    char error_text[sizeof(control->error_text) + 1];
    unsigned int length = control->error_len;
    if (length > sizeof(control->error_text)) {
        length = sizeof(control->error_text);
    }
    for (unsigned int i = 0; i < length; ++i) {
        error_text[i] = control->error_text[i];
    }
    error_text[length] = '\0';
    fprintf(stderr, "%s\n", error_text);
}

static void report_capsule_stop(const char* operation, int run_error, volatile const struct doom_bpf_ctrl* control) {
    if (control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
        fprintf(stderr, "%s: capsule stopped: %s (%lld)\n", operation, bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
    } else if (control->capsule.status == CAPSULE_EXITED) {
        fprintf(stderr, "%s: guest exited with code %lld\n", operation, (long long)control->capsule.code);
    } else {
        fprintf(stderr, "%s: %s; capsule status=%s\n", operation, run_error ? strerror(errno) : "phase did not finish in one invocation",
            bpf_capsule_status_string(control->capsule.status));
    }
    print_capsule_error_text(control);
}

static uint64_t monotonic_us(void) {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000000ull + (uint64_t)time.tv_nsec / 1000;
}

static uint64_t thread_cpu_ns(void) {
    struct timespec time;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &time);
    return (uint64_t)time.tv_sec * 1000000000ull + (uint64_t)time.tv_nsec;
}

static uint64_t program_run_time(int program_fd) {
    struct bpf_prog_info info = {0};
    unsigned int info_length = sizeof(info);
    return bpf_prog_get_info_by_fd(program_fd, &info, &info_length) ? 0 : info.run_time_ns;
}

static int framebuffer_is_readable(const struct bpf_capsule* capsule, const unsigned char* framebuffer) {
    uintptr_t memory = (uintptr_t)bpf_capsule_memory_start(capsule);
    uintptr_t address = (uintptr_t)framebuffer;
    uint64_t memory_size = bpf_capsule_memory_size(capsule);
    const uint64_t framebuffer_size = (uint64_t)W * H * 4;
    return framebuffer && address >= memory && memory_size >= framebuffer_size && address - memory <= memory_size - framebuffer_size;
}

struct terminal_output {
    char* bytes;
    size_t capacity;
    unsigned rows, columns;
};

// One terminal cell carries two independently coloured vertical pixels. With
// ordinary 1:2 terminal cells that makes square samples; fitting a 4:3 image
// therefore takes eight columns per three rows.
static int draw_terminal(struct terminal_output* output, const unsigned char* frame) {
    struct winsize window = {0};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) || !window.ws_col || !window.ws_row) {
        window.ws_col = 80;
        window.ws_row = 24;
    }
    unsigned rows = window.ws_row > 100 ? 100 : window.ws_row;
    unsigned columns = rows * 8 / 3;
    if (columns > window.ws_col) {
        columns = window.ws_col;
        rows = columns * 3 / 8;
    }
    if (!rows || !columns) {
        return -1;
    }

    size_t needed = (size_t)rows * columns * 48 + (size_t)rows * 24 + 32;
    if (needed > output->capacity) {
        char* bytes = realloc(output->bytes, needed);
        if (!bytes) {
            return -1;
        }
        output->bytes = bytes;
        output->capacity = needed;
    }

    char* at = output->bytes;
    if (output->rows != window.ws_row || output->columns != window.ws_col) {
        at += sprintf(at, "\033[2J\033[?25l");
        output->rows = window.ws_row;
        output->columns = window.ws_col;
    }
    unsigned top = (window.ws_row - rows) / 2 + 1;
    unsigned left = (window.ws_col - columns) / 2 + 1;
    unsigned last_foreground = ~0u, last_background = ~0u;
    for (unsigned y = 0; y < rows; y++) {
        at += sprintf(at, "\033[%u;%uH", top + y, left);
        unsigned source_top = (uint64_t)(2 * y) * H / (2 * rows);
        unsigned source_bottom = (uint64_t)(2 * y + 1) * H / (2 * rows);
        for (unsigned x = 0; x < columns; x++) {
            unsigned source_x = (uint64_t)x * W / columns;
            const unsigned char* foreground = frame + (source_top * W + source_x) * 4;
            const unsigned char* background = frame + (source_bottom * W + source_x) * 4;
            unsigned foreground_rgb = foreground[0] << 16 | foreground[1] << 8 | foreground[2];
            unsigned background_rgb = background[0] << 16 | background[1] << 8 | background[2];
            if (foreground_rgb != last_foreground || background_rgb != last_background) {
                at +=
                    sprintf(at, "\033[38;2;%u;%u;%u;48;2;%u;%u;%um", foreground[0], foreground[1], foreground[2], background[0], background[1], background[2]);
                last_foreground = foreground_rgb;
                last_background = background_rgb;
            }
            memcpy(at, "\xe2\x96\x80", 3); // U+2580 UPPER HALF BLOCK
            at += 3;
        }
    }
    memcpy(at, "\033[0m", 4);
    at += 4;
    if (fwrite(output->bytes, 1, (size_t)(at - output->bytes), stdout) != (size_t)(at - output->bytes)) {
        return -1;
    }
    return fflush(stdout) ? -1 : 0;
}

struct frame_samples {
    uint64_t* ns;
    size_t count;
    size_t capacity;
};

static int record_frame(struct frame_samples* samples, uint64_t ns) {
    if (samples->count == samples->capacity) {
        size_t grown = samples->capacity ? samples->capacity * 2 : 1024;
        uint64_t* data = realloc(samples->ns, grown * sizeof(*data));
        if (!data) {
            return -1;
        }
        samples->ns = data;
        samples->capacity = grown;
    }
    samples->ns[samples->count++] = ns;
    return 0;
}

static int compare_frame_ns(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return x < y ? -1 : x > y;
}

// Mean plus tail percentiles: frames are not uniform (screen wipes, busy
// scenes), and the slow tail is what a player actually notices.
static void print_frame_stats(struct frame_samples* samples, const char* engine) {
    if (!samples->count) {
        return;
    }
    qsort(samples->ns, samples->count, sizeof(*samples->ns), compare_frame_ns);
    uint64_t total = 0;
    for (size_t i = 0; i < samples->count; i++) {
        total += samples->ns[i];
    }
    size_t last = samples->count - 1;
    fprintf(stderr, "%s frame time over %zu frames: avg %.3f ms, p50 %.3f ms, p90 %.3f ms, p99 %.3f ms, max %.3f ms\n", engine, samples->count,
        total / 1e6 / samples->count, samples->ns[last * 50 / 100] / 1e6, samples->ns[last * 90 / 100] / 1e6, samples->ns[last * 99 / 100] / 1e6,
        samples->ns[last] / 1e6);
}

static int import_wad(FILE* file, unsigned char* destination, size_t size) {
    if (fread(destination, 1, size, file) == size) {
        return 0;
    }
    if (ferror(file)) {
        perror("WAD read");
    } else {
        fprintf(stderr, "WAD changed while it was being read\n");
    }
    return -1;
}

// doom_key_t values, from DOOM.h. Enter is accepted as both CR and LF: the
// terminal is left with ICRNL on, so Return arrives as '\n', not '\r'.
#define DK_ENTER 13
#define DK_ESCAPE 27
#define DK_SPACE 32
#define DK_CTRL (0x80 + 0x1d)
#define DK_UP 0xad
#define DK_DOWN 0xaf
#define DK_LEFT 0xac
#define DK_RIGHT 0xae

static int key_of_ascii(int code) {
    switch (code) {
        case 'w':
        case 'W':
            return DK_UP;
        case 's':
        case 'S':
            return DK_DOWN;
        case 'a':
        case 'A':
            return DK_LEFT;
        case 'd':
        case 'D':
            return DK_RIGHT;
        case '\r':
        case '\n':
            return DK_ENTER;
        case 27:
            return DK_ESCAPE;
        case ' ':
            return DK_SPACE;
        case 'f':
        case 'F':
            return DK_CTRL;
        default:
            return 0;
    }
}

static int write_ppm(const char* path, const unsigned char* pixels) {
    FILE* file = fopen(path, "wb");
    if (!file) {
        perror(path);
        return -1;
    }
    int failed = fprintf(file, "P6\n%d %d\n255\n", W, H) < 0;
    for (int i = 0; !failed && i < W * H; ++i) {
        failed = fwrite(pixels + i * 4, 1, 3, file) != 3;
    }
    if (fclose(file)) {
        failed = 1;
    }
    if (failed) {
        fprintf(stderr, "cannot write %s\n", path);
        return -1;
    }
    return 0;
}

// ---- the engine behind either the kernel or this process ---------------------

struct engine {
    int native;
    // the kernel
    struct doom* skeleton;
    struct bpf_capsule capsule;
    volatile struct doom_bpf_ctrl* ctrl;
    int start_fd, frame_fd, stats_fd;
    struct bpf_test_run_opts options;
    // this process
    unsigned char* wad;
    unsigned int events[DOOM_INPUT_QUEUE_CAPACITY];
    unsigned int event_count;
};

enum frame_status {
    FRAME_DRAWN = 0,
    FRAME_STOPPED = 1, // the game quit cleanly
    FRAME_FAILED = -1,
};

static int queue_input(struct engine* engine, int key, int down) {
    unsigned int event = (unsigned)key | (down ? DOOM_INPUT_DOWN : 0);
    if (engine->native) {
        if (engine->event_count >= DOOM_INPUT_QUEUE_CAPACITY) {
            fprintf(stderr, "input queue overflow: too many key transitions in one game tic\n");
            return -1;
        }
        engine->events[engine->event_count++] = event;
        return 0;
    }
    unsigned count = engine->ctrl->input_count;
    if (count >= DOOM_INPUT_QUEUE_CAPACITY) {
        fprintf(stderr, "input queue overflow: too many key transitions in one game tic\n");
        return -1;
    }
    engine->ctrl->input_events[count] = event;
    engine->ctrl->input_count = count + 1;
    return 0;
}

// Loads the WAD into the engine's memory and starts it. Startup and every
// frame must finish in one invocation: this example has no continuation-
// driving loop, so any non-OK status is a hard failure.
static int start_engine(struct engine* engine, FILE* wad, uint64_t wad_size, int start_in_e1m1) {
    if (engine->native) {
        engine->wad = malloc(wad_size);
        if (!engine->wad) {
            perror("allocate WAD");
            return -1;
        }
        if (import_wad(wad, engine->wad, (size_t)wad_size)) {
            return -1;
        }
        int exit_code = setjmp(native_exit_point);
        if (exit_code) {
            fprintf(stderr, "engine start failed: engine exited with code %d\n", exit_code - 1);
            return -1;
        }
        doom_engine_start(engine->wad, wad_size, start_in_e1m1);
        return 0;
    }

    const uint64_t engine_heap_size = 20ull << 20;
    engine->skeleton = doom__open();
    if (!engine->skeleton) {
        fprintf(stderr, "open failed\n");
        return -1;
    }
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = wad_size + engine_heap_size,
    };
    if (bpf_capsule_configure(&engine->capsule, engine->skeleton->obj, capsule_config) || bpf_object__load_skeleton(engine->skeleton->skeleton) ||
        bpf_capsule_initialize(&engine->capsule)) {
        fprintf(stderr, "failed to load BPF object: %s\n", strerror(errno));
        return -1;
    }
    engine->ctrl = &engine->skeleton->data_ctrl->ctrl;
    engine->frame_fd = bpf_program__fd(engine->skeleton->progs.doom_frame);
    engine->start_fd = bpf_program__fd(engine->skeleton->progs.doom_start);
    if (engine->frame_fd < 0 || engine->start_fd < 0) {
        fprintf(stderr, "BPF object is missing a Doom entry\n");
        return -1;
    }
    engine->options.sz = sizeof(engine->options);
    engine->stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    engine->ctrl->wad = bpf_capsule_malloc(&engine->capsule, wad_size);
    if (!engine->ctrl->wad) {
        perror("allocate WAD");
        return -1;
    }
    engine->ctrl->wad_size = wad_size;
    if (import_wad(wad, engine->ctrl->wad, (size_t)wad_size)) {
        return -1;
    }
    // Start the engine once, before any frame: in dump mode it warps straight
    // into E1M1 for determinism.
    engine->ctrl->start_in_e1m1 = start_in_e1m1;
    int start_error = bpf_prog_test_run_opts(engine->start_fd, &engine->options);
    if (start_error || engine->ctrl->capsule.status != CAPSULE_OK) {
        report_capsule_stop("engine start failed", start_error, engine->ctrl);
        return -1;
    }
    if ((int)engine->options.retval != 0) {
        fprintf(stderr, "engine start returned %d\n", (int)engine->options.retval);
        return -1;
    }
    return 0;
}

// One game tic and its frame. *ns receives the frame's execution time: kernel
// time from BPF's own accounting, or this thread's CPU time natively.
static enum frame_status run_frame(struct engine* engine, const unsigned char** framebuffer, uint64_t* ns) {
    if (engine->native) {
        int exit_code = setjmp(native_exit_point);
        if (exit_code) {
            engine->event_count = 0;
            if (exit_code - 1) {
                fprintf(stderr, "run stopped: engine exited with code %d\n", exit_code - 1);
                return FRAME_FAILED;
            }
            return FRAME_STOPPED;
        }
        uint64_t before = thread_cpu_ns();
        *framebuffer = doom_engine_frame(engine->events, engine->event_count);
        *ns = thread_cpu_ns() - before;
        engine->event_count = 0;
        return FRAME_DRAWN;
    }

    uint64_t before = program_run_time(engine->frame_fd);
    int frame_error = bpf_prog_test_run_opts(engine->frame_fd, &engine->options);
    if (frame_error || engine->ctrl->capsule.status != CAPSULE_OK) {
        report_capsule_stop("run stopped", frame_error, engine->ctrl);
        return engine->ctrl->capsule.status == CAPSULE_EXITED && engine->ctrl->capsule.code == 0 ? FRAME_STOPPED : FRAME_FAILED;
    }
    if ((int)engine->options.retval != 0) {
        fprintf(stderr, "frame returned %d\n", (int)engine->options.retval);
        return FRAME_FAILED;
    }
    *framebuffer = engine->ctrl->framebuffer;
    if (!framebuffer_is_readable(&engine->capsule, *framebuffer)) {
        fprintf(stderr, "framebuffer is outside Capsule memory\n");
        return FRAME_FAILED;
    }
    *ns = engine->stats_fd >= 0 ? program_run_time(engine->frame_fd) - before : 0;
    return FRAME_DRAWN;
}

static void release_engine(struct engine* engine) {
    if (engine->native) {
        free(engine->wad);
        return;
    }
    if (engine->stats_fd >= 0) {
        close(engine->stats_fd);
    }
    if (engine->skeleton) {
        (void)bpf_capsule_release(&engine->capsule);
        doom__destroy(engine->skeleton);
    }
}

int main(int argc, char** argv) {
    int native = argc >= 2 && !strcmp(argv[1], "--native");
    argc -= native;
    argv += native;
    if (argc < 3) {
        fprintf(stderr, "usage: doom [--native] WAD (tty | dump N DIR)\n");
        return 1;
    }
    int tty = !strcmp(argv[2], "tty"), dump = !strcmp(argv[2], "dump");
    if ((tty && argc != 3) || (dump && argc != 5) || (!tty && !dump)) {
        fprintf(stderr, "usage: doom [--native] WAD (tty | dump N DIR)\n");
        return 1;
    }

    long dump_frames = 0;
    if (dump) {
        char* end = NULL;
        errno = 0;
        dump_frames = strtol(argv[3], &end, 10);
        if (errno || *end || dump_frames < 1 || dump_frames > INT_MAX) {
            fprintf(stderr, "dump frame count must be an integer from 1 through %d\n", INT_MAX);
            return 1;
        }
    }

    int result = 1;
    int terminal_configured = 0;
    struct termios saved = {0};
    struct terminal_output terminal = {0};
    struct frame_samples samples = {0};
    struct engine engine = {.native = native, .stats_fd = -1};
    const char* engine_name = native ? "native" : "kernel";
    FILE* wad = fopen(argv[1], "rb");
    if (!wad) {
        perror(argv[1]);
        goto cleanup;
    }
    if (fseek(wad, 0, SEEK_END)) {
        perror("WAD size");
        goto cleanup;
    }
    long wad_file_size = ftell(wad);
    if (wad_file_size < 0) {
        perror("WAD size");
        goto cleanup;
    }
    if (!wad_file_size) {
        fprintf(stderr, "WAD must not be empty\n");
        goto cleanup;
    }
    if (wad_file_size > INT_MAX) {
        fprintf(stderr, "WAD is too large for PureDOOM\n");
        goto cleanup;
    }
    if (fseek(wad, 0, SEEK_SET)) {
        perror("WAD rewind");
        goto cleanup;
    }
    if (start_engine(&engine, wad, (uint64_t)wad_file_size, dump)) {
        goto cleanup;
    }
    int wad_close_error = fclose(wad);
    wad = NULL;
    if (wad_close_error) {
        perror("WAD close");
        goto cleanup;
    }

    if (dump) { // deterministic input and PPMs out
        int dump_failed = 0;
        for (int i = 0; i < (int)dump_frames; ++i) {
            const unsigned char* framebuffer = NULL;
            uint64_t ns = 0;
            if (run_frame(&engine, &framebuffer, &ns) != FRAME_DRAWN) {
                dump_failed = 1;
                break;
            }
            if (record_frame(&samples, ns)) {
                fprintf(stderr, "cannot record frame timing\n");
                dump_failed = 1;
                break;
            }
            if (i == 6 && queue_input(&engine, DK_UP, 1)) {
                dump_failed = 1;
                break;
            }
            if (i == 7 && queue_input(&engine, DK_RIGHT, 1)) {
                dump_failed = 1;
                break;
            }
            char ppm[PATH_MAX];
            int name_length = snprintf(ppm, sizeof(ppm), "%s/frame_%05d.ppm", argv[4], i);
            if (name_length < 0 || (size_t)name_length >= sizeof(ppm)) {
                fprintf(stderr, "frame output path is too long\n");
                dump_failed = 1;
                break;
            }
            if (write_ppm(ppm, framebuffer)) {
                dump_failed = 1;
                break;
            }
        }
        fprintf(stderr, dump_failed ? "dump failed\n" : "dump done: status=0\n");
        result = dump_failed;
        goto cleanup;
    }

    if (signal(SIGINT, request_stop) == SIG_ERR || signal(SIGTERM, request_stop) == SIG_ERR) {
        perror("signal");
        goto cleanup;
    }

    uint64_t t0 = 0, tick = 0;
    struct termios raw;
    if (tcgetattr(STDIN_FILENO, &saved)) {
        perror("tcgetattr");
        goto cleanup;
    }
    raw = saved;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw)) {
        perror("tcsetattr");
        goto cleanup;
    }
    terminal_configured = 1;

    int failed = 0;
    int held = 0, linger = 0;
    while (!stop_requested) {
        // A terminal delivers keystrokes, not press/release pairs, so a key
        // sent down is never sent up and DOOM holds it forever. Synthesize the
        // release after a few tics; terminal auto-repeat refreshes it while the
        // key is physically held.
        int pressed = 0;
        char buf[64];
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n < 0 && errno != EINTR && errno != EAGAIN) {
            perror("terminal input");
            failed = 1;
            break;
        }
        for (ssize_t i = 0; i < n; i++) {
            int k;
            // Arrow keys arrive as ESC [ A..D. Read them as arrows, or a lone
            // ESC swallows them and opens the menu instead.
            if (buf[i] == 27 && i + 2 < n && buf[i + 1] == '[') {
                switch (buf[i + 2]) {
                    case 'A':
                        k = DK_UP;
                        break;
                    case 'B':
                        k = DK_DOWN;
                        break;
                    case 'C':
                        k = DK_RIGHT;
                        break;
                    case 'D':
                        k = DK_LEFT;
                        break;
                    default:
                        k = 0;
                        break;
                }
                i += 2;
            } else {
                k = key_of_ascii((unsigned char)buf[i]);
            }
            if (k) {
                pressed = k;
            }
        }
        if (pressed) {
            if (pressed != held) {
                if ((held && queue_input(&engine, held, 0)) || queue_input(&engine, pressed, 1)) {
                    failed = 1;
                    break;
                }
                held = pressed;
            }
            linger = 6;
        } else if (held && --linger <= 0) {
            if (queue_input(&engine, held, 0)) {
                failed = 1;
                break;
            }
            held = 0;
        }
        // PureDOOM advances exactly one game tic per call; pace those calls at
        // the engine's native 35 Hz.
        if (!t0) {
            t0 = monotonic_us();
        }
        uint64_t due = ++tick * 1000000ull / 35;
        const unsigned char* framebuffer = NULL;
        uint64_t ns = 0;
        enum frame_status status = run_frame(&engine, &framebuffer, &ns);
        if (status != FRAME_DRAWN) {
            failed = status == FRAME_FAILED;
            break;
        }
        if (record_frame(&samples, ns)) {
            fprintf(stderr, "cannot record frame timing\n");
            failed = 1;
            break;
        }
        if (draw_terminal(&terminal, framebuffer)) {
            failed = 1;
            break;
        }
        // Account for both the frame and userspace presentation. Using the
        // timestamp from before that work would add its duration to every
        // 1/35-second period and make busy scenes visibly slow down.
        uint64_t now = monotonic_us();
        int64_t slack = (int64_t)(t0 + due) - (int64_t)now;
        if (slack > 0 && usleep((useconds_t)slack) && errno != EINTR) {
            perror("frame pacing");
            failed = 1;
            break;
        }
    }
    result = failed;

cleanup:
    if (terminal_configured) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &saved)) {
            perror("restore terminal");
            result = 1;
        }
        if (fputs("\033[0m\033[?25h\033[2J\033[H", stdout) == EOF || fflush(stdout)) {
            result = 1;
        }
    }
    print_frame_stats(&samples, engine_name);
    free(samples.ns);
    free(terminal.bytes);
    if (wad) {
        fclose(wad);
    }
    release_engine(&engine);
    return result;
}
