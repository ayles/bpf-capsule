// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// One integer-only Rust workload for native, stock eBPF and transformed eBPF.
// The deliberately unsafe byte accessor avoids adding Rust panic paths to the
// measured program; its explicit power-of-two mask is the actual memory-safety
// proof consumed by the eBPF verifier.
#![no_std]

use core::hint::black_box;

const PACKET_COUNT: u32 = 16;
const PACKET_BYTES: u32 = 128;
const INPUT_BYTES: u32 = PACKET_COUNT * PACKET_BYTES;

unsafe extern "C" {
    static rust_oh_input: [u8; INPUT_BYTES as usize];
    fn rust_oh_abort() -> !;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { rust_oh_abort() }
}

#[inline(always)]
fn byte(packet: u32, offset: u32) -> u8 {
    let index = black_box(packet.wrapping_mul(PACKET_BYTES).wrapping_add(offset))
        & (INPUT_BYTES - 1);
    unsafe { *core::ptr::addr_of!(rust_oh_input).cast::<u8>().add(index as usize) }
}

#[inline(always)]
fn be16(packet: u32, offset: u32) -> u32 {
    ((byte(packet, offset) as u32) << 8) | byte(packet, offset + 1) as u32
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_oh_mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_oh_classify(packet: u32) -> u64 {
    let mut cursor = 12;
    let mut ether_type = be16(packet, cursor);
    cursor = 14;

    for _ in 0..2 {
        if ether_type != 0x8100 && ether_type != 0x88a8 {
            break;
        }
        ether_type = be16(packet, cursor + 2);
        cursor += 4;
    }
    if ether_type != 0x0800 {
        return rust_oh_mix(0x45544800 | ether_type as u64);
    }

    let version_ihl = byte(packet, cursor) as u32;
    let ihl = (version_ihl & 15) * 4;
    if version_ihl >> 4 != 4 || ihl < 20 || ihl > 60 || cursor + ihl > 96 {
        return rust_oh_mix(0x49503400 | version_ihl as u64);
    }

    let total = be16(packet, cursor + 2);
    let fragment = be16(packet, cursor + 6);
    let protocol = byte(packet, cursor + 9) as u32;
    let src = (be16(packet, cursor + 12) << 16) | be16(packet, cursor + 14);
    let dst = (be16(packet, cursor + 16) << 16) | be16(packet, cursor + 18);
    let l4 = cursor + ihl;
    if fragment & 0x1fff != 0 || total < ihl + 8 || l4 + 8 > PACKET_BYTES {
        return rust_oh_mix(((src as u64) << 32) | dst as u64);
    }

    let sport = be16(packet, l4);
    let dport = be16(packet, l4 + 2);
    let mut payload = l4 + 8;
    let mut state = ((src as u64) << 32) | dst as u64;
    state ^= ((sport as u64) << 48)
        | ((dport as u64) << 32)
        | ((protocol as u64) << 24)
        | total as u64;

    if protocol == 6 && l4 + 20 <= PACKET_BYTES {
        let tcp_bytes = ((byte(packet, l4 + 12) as u32) >> 4) * 4;
        if tcp_bytes < 20 || tcp_bytes > 60 || l4 + tcp_bytes > PACKET_BYTES {
            return rust_oh_mix(state ^ 0xbad70000);
        }
        state ^= (byte(packet, l4 + 13) as u64) << 8;

        let mut option = l4 + 20;
        let end = l4 + tcp_bytes;
        for n in 0..10u32 {
            if option >= end {
                break;
            }
            let kind = byte(packet, option) as u32;
            state = (state << 7) ^ (state >> 3) ^ kind as u64;
            if kind == 0 {
                break;
            }
            if kind == 1 {
                option += 1;
                continue;
            }
            if option + 1 >= end {
                break;
            }
            let length = byte(packet, option + 1) as u32;
            if length < 2 || option + length > end {
                break;
            }
            state ^= (length as u64) << ((n & 7) * 8);
            option += length;
        }
        payload = l4 + tcp_bytes;
    }

    for n in 0..48u32 {
        state ^= byte(packet, payload + n) as u64;
        state = state.wrapping_mul(0x100000001b3);
        state ^= state >> 29;
    }

    let pass = dport == 53
        || dport == 443
        || dport == 8443
        || (protocol == 6 && state & 31 == 0);
    (rust_oh_mix(state ^ ((pass as u64) << 63)) & 0x7fff_ffff_ffff_ffff)
        | ((pass as u64) << 63)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_oh_workload() -> u64 {
    let mut digest = 0x6a09e667f3bcc909u64;
    let mut accepted = 0u32;
    for packet in 0..PACKET_COUNT {
        let value = rust_oh_classify(packet);
        accepted += (value >> 63) as u32;
        digest = rust_oh_mix(digest ^ value ^ ((packet as u64) << 40));
    }
    rust_oh_mix(digest ^ ((accepted as u64) << 32) ^ PACKET_COUNT as u64)
}
