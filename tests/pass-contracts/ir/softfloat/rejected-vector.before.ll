source_filename = "softfloat-rejected-vector.ll"
target triple = "bpfel"

define <2 x float> @vector(<2 x float> %value) {
entry:
  ret <2 x float> %value
}
