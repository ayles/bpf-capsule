source_filename = "softfloat-rejected-wide.ll"
target triple = "bpfel"

define fp128 @wide(fp128 %value) {
entry:
  ret fp128 %value
}
