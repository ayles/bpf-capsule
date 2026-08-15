// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Minimal `no_std` support for Rust code compiled as Capsule-managed bitcode.
//!
//! The default feature supplies a panic handler which terminates the managed
//! computation. The `alloc` feature additionally
//! installs a global allocator backed by the freestanding Capsule `malloc`,
//! `memalign`, and `free` symbols linked by `bpf_capsule_rust_bitcode()`.
//! This crate owns no maps or execution state; the C translation unit including
//! `bpf_capsule.c` supplies the object runtime and entry programs.
#![no_std]

#[cfg(feature = "alloc")]
use core::alloc::{GlobalAlloc, Layout};

#[cfg(target_arch = "bpf")]
unsafe extern "C" {
    // The single Capsule termination primitive; the code space is a shell's:
    // 0..255 is the guest's, negative is the framework's.
    fn __bpf_capsule_exit(code: i32) -> !;
}

#[cfg(not(target_arch = "bpf"))]
unsafe extern "C" {
    fn abort() -> !;
}

#[cfg(feature = "alloc")]
unsafe extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn memalign(alignment: usize, size: usize) -> *mut u8;
    fn free(pointer: *mut u8);
}

#[cfg(feature = "alloc")]
struct CapsuleAllocator;

#[cfg(feature = "alloc")]
unsafe impl GlobalAlloc for CapsuleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= 8 {
            unsafe { malloc(layout.size()) }
        } else {
            unsafe { memalign(layout.align(), layout.size()) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        unsafe { free(pointer) }
    }
}

#[cfg(feature = "alloc")]
#[global_allocator]
static ALLOCATOR: CapsuleAllocator = CapsuleAllocator;

#[panic_handler]
fn panic(_information: &core::panic::PanicInfo<'_>) -> ! {
    // A std Rust process exits 101 on panic; the capsule guest matches it.
    #[cfg(target_arch = "bpf")]
    unsafe {
        __bpf_capsule_exit(101)
    }

    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        abort()
    }
}
