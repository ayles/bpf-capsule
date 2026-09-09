// SPDX-License-Identifier: GPL-2.0-only
// PureDOOM's platform boundary, shared by the kernel guest and the native
// comparison build: the WAD read from memory, a 35 Hz frame clock, memory from
// malloc, and the two engine steps. The includer defines how a fatal
// doom_exit() and the first "Error:" line are delivered.
#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "DOOM.h"
#include "doom_config.h"

#ifndef DOOM_ENGINE_EXIT
#error "define DOOM_ENGINE_EXIT(code) before including doom_engine.h"
#endif
#ifndef DOOM_ENGINE_ERROR
#error "define DOOM_ENGINE_ERROR(text, length) before including doom_engine.h"
#endif

struct doom_engine_wad {
    const unsigned char* data;
    unsigned long size;
    unsigned long position;
};

static struct doom_engine_wad doom_engine_wad;
static uint64_t doom_engine_clock;
static int doom_engine_started;

static const char* doom_engine_basename(const char* path) {
    const char* name = path;
    for (; *path; path++) {
        if (*path == '/' || *path == '\\') {
            name = path + 1;
        }
    }
    return name;
}

static void* doom_engine_malloc(int size) {
    if (size <= 0) {
        return 0;
    }
    void* result = malloc((unsigned long)size);
    if (!result) {
        DOOM_ENGINE_EXIT(1);
    }
    return result;
}

static void* doom_engine_open(const char* path, const char* mode) {
    if (!mode || mode[0] != 'r' || doom_strcmp(doom_engine_basename(path), "doom1.wad")) {
        return 0;
    }
    doom_engine_wad.position = 0;
    return &doom_engine_wad;
}

static int doom_engine_read(void* handle, void* destination, int count) {
    if (handle != &doom_engine_wad || count <= 0) {
        return count == 0 ? 0 : -1;
    }
    unsigned long left = doom_engine_wad.size - doom_engine_wad.position;
    unsigned long length = (unsigned long)count;
    if (length > left) {
        length = left;
    }
    doom_memcpy(destination, doom_engine_wad.data + doom_engine_wad.position, (int)length);
    doom_engine_wad.position += length;
    return (int)length;
}

static int doom_engine_seek(void* handle, int offset, doom_seek_t origin) {
    if (handle != &doom_engine_wad) {
        return -1;
    }
    long base = 0;
    if (origin == DOOM_SEEK_CUR) {
        base = (long)doom_engine_wad.position;
    } else if (origin == DOOM_SEEK_END) {
        base = (long)doom_engine_wad.size;
    } else if (origin != DOOM_SEEK_SET) {
        return -1;
    }
    long position = base + offset;
    if (position < 0 || (unsigned long)position > doom_engine_wad.size) {
        return -1;
    }
    doom_engine_wad.position = (unsigned long)position;
    return 0;
}

static int doom_engine_tell(void* handle) {
    return handle == &doom_engine_wad ? (int)doom_engine_wad.position : -1;
}

static int doom_engine_eof(void* handle) {
    return handle != &doom_engine_wad || doom_engine_wad.position >= doom_engine_wad.size;
}

static void doom_engine_gettime(int* seconds, int* microseconds) {
    *seconds = (int)(doom_engine_clock / 35);
    *microseconds = (int)(doom_engine_clock % 35) * 1000000 / 35;
}

static char* doom_engine_getenv(const char* name) {
    return doom_strcmp(name, "HOME") == 0 ? "." : 0;
}

static void doom_engine_exit(int code) {
    DOOM_ENGINE_EXIT(code);
}

// PureDOOM reports fatal errors through its print callback immediately before
// doom_exit(); the first "Error:" line is the explanation worth keeping.
static void doom_engine_print(const char* text) {
    int length = doom_strlen(text);
    if (length >= 6 && text[0] == 'E' && text[1] == 'r' && text[2] == 'r' && text[3] == 'o' && text[4] == 'r' && text[5] == ':') {
        DOOM_ENGINE_ERROR(text, length);
    }
}

// Engine start-up: WAD parsing, zone setup and the initial level load. In
// deterministic mode it warps straight into E1M1.
static void doom_engine_start(const unsigned char* wad, unsigned long wad_size, int start_in_e1m1) {
    doom_engine_wad.data = wad;
    doom_engine_wad.size = wad_size;
    doom_engine_wad.position = 0;
    doom_set_print(doom_engine_print);
    doom_set_malloc(doom_engine_malloc, free);
    // Null selects PureDOOM's no-op close and failing write defaults. The
    // in-memory WAD handle owns no resource, and nothing else is a file.
    doom_set_file_io(doom_engine_open, 0, doom_engine_read, 0, doom_engine_seek, doom_engine_tell, doom_engine_eof);
    doom_set_gettime(doom_engine_gettime);
    doom_set_exit(doom_engine_exit);
    doom_set_getenv(doom_engine_getenv);

    char* argv[] = {"bpf-doom", "-warp", "1", "1"};
    doom_init(start_in_e1m1 ? 4 : 1, argv, DOOM_FLAG_HIDE_MOUSE_OPTIONS | DOOM_FLAG_HIDE_SOUND_OPTIONS | DOOM_FLAG_HIDE_MUSIC_OPTIONS);
    doom_engine_started = 1;
}

// One frame: deliver the queued key transitions, advance one game tic, render.
// The engine must already be started; a frame never initializes.
static const unsigned char* doom_engine_frame(const unsigned int* events, unsigned count) {
    if (!doom_engine_started) {
        DOOM_ENGINE_EXIT(1);
    }
    for (unsigned i = 0; i < count; i++) {
        unsigned event = events[i];
        int key = (int)(event & DOOM_INPUT_KEY_MASK);
        if (event & DOOM_INPUT_DOWN) {
            doom_key_down(key);
        } else {
            doom_key_up(key);
        }
    }
    doom_force_update();
    doom_engine_clock++;
    return doom_get_framebuffer(4);
}
