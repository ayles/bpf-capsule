// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Minimal `no_std` support for Rust code compiled as Capsule-managed bitcode.
#![no_std]

#[cfg(feature = "alloc")]
use core::alloc::{GlobalAlloc, Layout};

#[cfg(target_arch = "bpf")]
unsafe extern "C" {
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
    #[cfg(target_arch = "bpf")]
    unsafe {
        __bpf_capsule_exit(101)
    }

    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        abort()
    }
}
