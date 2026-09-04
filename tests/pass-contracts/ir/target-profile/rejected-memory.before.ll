source_filename = "rejected-memory.c"
target triple = "bpfel"

@__bpf_capsule_memory_backend = constant i32 0

define void @entry() {
  ret void
}
