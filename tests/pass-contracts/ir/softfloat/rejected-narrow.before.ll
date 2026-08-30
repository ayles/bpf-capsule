source_filename = "softfloat-rejected-narrow.ll"
target triple = "bpfel"

define half @narrow(half %value) {
entry:
  ret half %value
}
