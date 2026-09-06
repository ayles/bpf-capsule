# Csmith differential test

The test project generates a fixed-seed integer and 128-bit Csmith program and
compares its checksum between native execution and Capsule on every target
profile. It exercises integer arithmetic and memory access; floating point is
covered separately by the [libc tests](../libc).
