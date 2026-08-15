// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

// A bounded packet-classification workload shared verbatim by the native,
// stock-eBPF and transformed-eBPF builds.  It deliberately uses only integer
// operations that both the CPU and eBPF JIT implement directly: no soft
// float, allocator, logging or helpers are part of the timed region.

typedef unsigned char oh_u8;
typedef unsigned int oh_u32;
typedef uint64_t oh_u64;

#define OH_PACKET_COUNT 16u
#define OH_PACKET_BYTES 128u
#define OH_INPUT_BYTES (OH_PACKET_COUNT * OH_PACKET_BYTES)

#define OH_NOINLINE __attribute__((noinline))

struct oh_result {
    oh_u64 digest;
    oh_u32 accepted;
    oh_u32 parsed;
};

extern oh_u8 oh_input[OH_INPUT_BYTES];

static __attribute__((always_inline)) oh_u8 oh_byte(oh_u32 packet, oh_u32 offset) {
    // The mask is redundant for the valid generated packets, but makes the
    // same safety proof explicit to Linux 5.15's verifier.
    oh_u32 index = packet * OH_PACKET_BYTES + offset;
    __asm__ volatile("" : "+r"(index));
    index &= OH_INPUT_BYTES - 1;
    return oh_input[index];
}

static __attribute__((always_inline)) oh_u32 oh_be16(oh_u32 packet, oh_u32 offset) {
    return ((oh_u32)oh_byte(packet, offset) << 8) | oh_byte(packet, offset + 1);
}

OH_NOINLINE oh_u64 oh_mix(oh_u64 x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

OH_NOINLINE oh_u64 oh_classify_packet(oh_u32 packet) {
    oh_u32 cursor = 12;
    oh_u32 ether_type = oh_be16(packet, cursor);
    cursor = 14;

    // Up to two VLAN tags.
    for (oh_u32 tag = 0; tag < 2; tag++) {
        if (ether_type != 0x8100 && ether_type != 0x88a8) {
            break;
        }
        ether_type = oh_be16(packet, cursor + 2);
        cursor += 4;
    }
    if (ether_type != 0x0800) {
        return oh_mix(0x45544800ULL | ether_type);
    }

    oh_u8 version_ihl = oh_byte(packet, cursor);
    oh_u32 ihl = (version_ihl & 15u) * 4u;
    if ((version_ihl >> 4) != 4 || ihl < 20 || ihl > 60 || cursor + ihl > 96) {
        return oh_mix(0x49503400ULL | version_ihl);
    }

    oh_u32 total = oh_be16(packet, cursor + 2);
    oh_u32 frag = oh_be16(packet, cursor + 6);
    oh_u32 protocol = oh_byte(packet, cursor + 9);
    oh_u32 src = ((oh_u32)oh_be16(packet, cursor + 12) << 16) | oh_be16(packet, cursor + 14);
    oh_u32 dst = ((oh_u32)oh_be16(packet, cursor + 16) << 16) | oh_be16(packet, cursor + 18);
    oh_u32 l4 = cursor + ihl;
    if ((frag & 0x1fff) || total < ihl + 8 || l4 + 8 > OH_PACKET_BYTES) {
        return oh_mix(((oh_u64)src << 32) | dst);
    }

    oh_u32 sport = oh_be16(packet, l4);
    oh_u32 dport = oh_be16(packet, l4 + 2);
    oh_u32 payload = l4 + 8;
    oh_u64 state = ((oh_u64)src << 32) | dst;
    state ^= ((oh_u64)sport << 48) | ((oh_u64)dport << 32) | ((oh_u64)protocol << 24) | total;

    if (protocol == 6 && l4 + 20 <= OH_PACKET_BYTES) {
        oh_u32 tcp_bytes = (oh_byte(packet, l4 + 12) >> 4) * 4u;
        if (tcp_bytes < 20 || tcp_bytes > 60 || l4 + tcp_bytes > OH_PACKET_BYTES) {
            return oh_mix(state ^ 0xBAD70000ULL);
        }
        state ^= (oh_u64)oh_byte(packet, l4 + 13) << 8;

        // Parse bounded TCP options rather than merely hashing fixed offsets.
        oh_u32 option = l4 + 20;
        oh_u32 end = l4 + tcp_bytes;
        for (oh_u32 n = 0; n < 10 && option < end; n++) {
            oh_u32 kind = oh_byte(packet, option);
            state = (state << 7) ^ (state >> 3) ^ kind;
            if (kind == 0) {
                break;
            }
            if (kind == 1) {
                option++;
                continue;
            }
            if (option + 1 >= end) {
                break;
            }
            oh_u32 length = oh_byte(packet, option + 1);
            if (length < 2 || option + length > end) {
                break;
            }
            state ^= (oh_u64)length << ((n & 7) * 8);
            option += length;
        }
        payload = l4 + tcp_bytes;
    }

    // A short payload fingerprint gives the JIT a realistic mixture of byte
    // loads, branches, shifts and 64-bit multiplies.
    for (oh_u32 n = 0; n < 48; n++) {
        state ^= oh_byte(packet, payload + n);
        state *= 0x100000001b3ULL;
        state ^= state >> 29;
    }

    oh_u32 pass = (dport == 53 || dport == 443 || dport == 8443 || (protocol == 6 && (state & 31) == 0));
    return (oh_mix(state ^ ((oh_u64)pass << 63)) & 0x7fffffffffffffffULL) | ((oh_u64)pass << 63);
}

static OH_NOINLINE void oh_workload(struct oh_result* result) {
    oh_u64 digest = 0x6a09e667f3bcc909ULL;
    oh_u32 accepted = 0;
    for (oh_u32 packet = 0; packet < OH_PACKET_COUNT; packet++) {
        oh_u64 value = oh_classify_packet(packet);
        accepted += (oh_u32)(value >> 63);
        digest = oh_mix(digest ^ value ^ ((oh_u64)packet << 40));
    }
    result->digest = digest;
    result->accepted = accepted;
    result->parsed = OH_PACKET_COUNT;
}
