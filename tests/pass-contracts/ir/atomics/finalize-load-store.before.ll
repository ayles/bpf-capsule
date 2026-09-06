source_filename = "finalize-atomic-load-store.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @atomic_access(ptr %pointer, i64 %value) {
entry:
  %old = load atomic volatile i64, ptr %pointer monotonic, align 8
  store atomic volatile i64 %value, ptr %pointer unordered, align 8
  %plain = load i64, ptr %pointer, align 8
  %result = add i64 %old, %plain
  ret i64 %result
}

define i64 @relaxed_fetches(ptr %p32, ptr %p64, i32 %v32, i64 %v64) {
entry:
  %a32 = atomicrmw add ptr %p32, i32 %v32 monotonic, align 4
  %s32 = atomicrmw sub ptr %p32, i32 %a32 monotonic, align 4
  %b32 = atomicrmw and ptr %p32, i32 %s32 monotonic, align 4
  %o32 = atomicrmw or ptr %p32, i32 %b32 monotonic, align 4
  %x32 = atomicrmw xor ptr %p32, i32 %o32 monotonic, align 4
  %wide = zext i32 %x32 to i64
  %a64 = atomicrmw add ptr %p64, i64 %wide monotonic, align 8
  %s64 = atomicrmw sub ptr %p64, i64 %a64 monotonic, align 8
  %b64 = atomicrmw and ptr %p64, i64 %s64 monotonic, align 8
  %o64 = atomicrmw or ptr %p64, i64 %b64 monotonic, align 8
  %x64 = atomicrmw xor ptr %p64, i64 %o64 monotonic, align 8
  %unused = atomicrmw add ptr %p64, i64 %v64 monotonic, align 8
  %ordered = atomicrmw xchg ptr %p64, i64 %x64 acquire, align 8
  ret i64 %ordered
}
