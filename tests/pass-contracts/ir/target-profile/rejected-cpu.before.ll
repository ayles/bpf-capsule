source_filename = "rejected-cpu.c"
target triple = "bpfel"

define i32 @compiled_for_v3() #0 {
  ret i32 0
}

attributes #0 = { "target-cpu"="v3" }
