#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Generate tiny deterministic llama2.c v0 and Q8-v2 VM-test checkpoints."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


# dim, hidden_dim, layers, query heads, key/value heads, vocabulary, context
# The context covers the examples' maximum 32-token request.
CONFIG = (8, 16, 1, 2, 1, 16, 64)
DIM, HIDDEN, LAYERS, HEADS, KV_HEADS, VOCAB, SEQ_LEN = CONFIG
HEAD_SIZE = DIM // HEADS
KV_DIM = DIM * KV_HEADS // HEADS
GROUP_SIZE = DIM


def f32(values: list[float]) -> bytes:
    return struct.pack(f"<{len(values)}f", *values)


def embeddings() -> list[float]:
    """Give token 15 a wide, stable classifier margin over every other row."""
    values = [0.0] * (VOCAB * DIM)
    for column in range(DIM):
        values[1 * DIM + column] = (column + 1) / 8.0
        values[15 * DIM + column] = (column + 1) * 1.25
    return values


def write_float(path: Path) -> None:
    # This is llama2.c's legacy/v0 layout. Attention and feed-forward matrices
    # are zero, so residuals retain the embedding. Shared classifier weights
    # then select token 15 by a large margin on every step.
    tensors = [
        embeddings(),
        [1.0] * (LAYERS * DIM),                          # attention RMS
        [0.0] * (LAYERS * DIM * DIM),                   # Wq
        [0.0] * (LAYERS * DIM * KV_DIM),                # Wk
        [0.0] * (LAYERS * DIM * KV_DIM),                # Wv
        [0.0] * (LAYERS * DIM * DIM),                   # Wo
        [1.0] * (LAYERS * DIM),                          # FFN RMS
        [0.0] * (LAYERS * DIM * HIDDEN),                # W1
        [0.0] * (LAYERS * HIDDEN * DIM),                # W2
        [0.0] * (LAYERS * DIM * HIDDEN),                # W3
        [1.0] * DIM,                                     # final RMS
        [0.0] * (SEQ_LEN * HEAD_SIZE // 2),              # legacy RoPE cos
        [0.0] * (SEQ_LEN * HEAD_SIZE // 2),              # legacy RoPE sin
    ]
    path.write_bytes(struct.pack("<7i", *CONFIG) +
                     b"".join(f32(tensor) for tensor in tensors))


def quantized_tensor(values: list[int], scales: list[float]) -> bytes:
    if len(values) % GROUP_SIZE or len(scales) != len(values) // GROUP_SIZE:
        raise ValueError("invalid Q8 tensor shape")
    return struct.pack(f"<{len(values)}b", *values) + f32(scales)


def zero_q8(size: int) -> bytes:
    return quantized_tensor([0] * size, [1.0] * (size // GROUP_SIZE))


def write_q8(path: Path) -> None:
    # Version 2 starts with a fixed 256-byte header. Each vocabulary row is one
    # Q8 group; rows 1 and 15 mirror the fp32 fixture and all matrix weights are
    # zero. Non-zero stored scales avoid malformed weight tensors.
    header = bytearray(256)
    struct.pack_into("<II7iBi", header, 0, 0x616B3432, 2, *CONFIG, 1,
                     GROUP_SIZE)

    tokens = [0] * (VOCAB * DIM)
    for column in range(DIM):
        tokens[1 * DIM + column] = column + 1
        tokens[15 * DIM + column] = (column + 1) * 10
    token_scales = [1.0] * VOCAB
    token_scales[1] = 0.125
    token_scales[15] = 0.125

    body = [
        f32([1.0] * (LAYERS * DIM)),                     # attention RMS
        f32([1.0] * (LAYERS * DIM)),                     # FFN RMS
        f32([1.0] * DIM),                                # final RMS
        quantized_tensor(tokens, token_scales),
        zero_q8(LAYERS * DIM * DIM),                     # Wq
        zero_q8(LAYERS * DIM * KV_DIM),                  # Wk
        zero_q8(LAYERS * DIM * KV_DIM),                  # Wv
        zero_q8(LAYERS * DIM * DIM),                     # Wo
        zero_q8(LAYERS * DIM * HIDDEN),                  # W1
        zero_q8(LAYERS * HIDDEN * DIM),                  # W2
        zero_q8(LAYERS * DIM * HIDDEN),                  # W3
    ]
    path.write_bytes(bytes(header) + b"".join(body))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    float_path = args.directory / "llama2-tiny.bin"
    q8_path = args.directory / "llama2q-tiny.bin"
    write_float(float_path)
    write_q8(q8_path)
    print(float_path.resolve())
    print(q8_path.resolve())


if __name__ == "__main__":
    main()
