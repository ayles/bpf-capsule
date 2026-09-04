# Csmith differential test

The test project generates a fixed, terminating integer and 128-bit Csmith
program and runs the same translation unit natively and through Capsule. Every
target profile therefore checks the same generated program. Its checksum is a
quick tripwire for arrays, pointers, aggregates, bitfields, packed layouts,
volatile objects, division, and Csmith's safe-math helpers. Floating point has
separate focused contracts: Csmith checksums require bit-for-bit host agreement,
while Capsule's compact single-precision division does not promise identical
rounding.
