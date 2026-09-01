#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Convert a legacy llama2.c fp32 checkpoint to its Q8-v2 format."""

from __future__ import annotations

import argparse
import struct
import sys
from array import array
from pathlib import Path


MAX_GROUP_SIZE = 64
CONFIG = struct.Struct("<7i")


def read_floats(image: memoryview, offset: int, count: int) -> tuple[array[float], int]:
    size = count * 4
    end = offset + size
    if end > len(image):
        raise ValueError("checkpoint is truncated")
    values = array("f")
    values.frombytes(image[offset:end])
    if sys.byteorder != "little":
        values.byteswap()
    return values, end


def quantize(values: array[float], group_size: int) -> bytes:
    if len(values) % group_size:
        raise ValueError("tensor size is not divisible by the Q8 group size")

    quantized = array("b")
    scales: list[float] = []
    for start in range(0, len(values), group_size):
        group = values[start : start + group_size]
        maximum = max(abs(value) for value in group)
        scale = maximum / 127.0
        scales.append(scale)
        if scale == 0.0:
            quantized.extend([0] * group_size)
        else:
            quantized.extend(max(-127, min(127, round(value / scale))) for value in group)
    return quantized.tobytes() + struct.pack(f"<{len(scales)}f", *scales)


def quantize_layers(values: array[float], layers: int, group_size: int) -> bytes:
    layer_size = len(values) // layers
    return b"".join(
        quantize(values[start : start + layer_size], group_size)
        for start in range(0, len(values), layer_size)
    )


def convert(source: Path, destination: Path) -> None:
    image = memoryview(source.read_bytes())
    if len(image) < CONFIG.size:
        raise ValueError("checkpoint is shorter than its configuration")

    dim, hidden, layers, heads, kv_heads, signed_vocab, context = CONFIG.unpack_from(image)
    if min(dim, hidden, layers, heads, kv_heads, context) <= 0 or signed_vocab == 0:
        raise ValueError("checkpoint has an invalid configuration")
    if dim % heads or heads % kv_heads:
        raise ValueError("checkpoint has an invalid attention layout")
    vocabulary = abs(signed_vocab)
    shared_classifier = signed_vocab > 0
    kv_dim = dim * kv_heads // heads
    head_size = dim // heads
    group_size = MAX_GROUP_SIZE
    while dim % group_size or hidden % group_size:
        group_size //= 2

    offset = CONFIG.size

    def take(count: int) -> array[float]:
        nonlocal offset
        values, offset = read_floats(image, offset, count)
        return values

    embeddings = take(vocabulary * dim)
    attention_norm = take(layers * dim)
    wq = take(layers * dim * dim)
    wk = take(layers * dim * kv_dim)
    wv = take(layers * dim * kv_dim)
    wo = take(layers * dim * dim)
    ffn_norm = take(layers * dim)
    w1 = take(layers * dim * hidden)
    w2 = take(layers * hidden * dim)
    w3 = take(layers * dim * hidden)
    final_norm = take(dim)
    take(context * head_size // 2)  # legacy RoPE cosine table
    take(context * head_size // 2)  # legacy RoPE sine table
    classifier = None if shared_classifier else take(vocabulary * dim)
    if offset != len(image):
        raise ValueError("checkpoint contains trailing data")

    header = bytearray(256)
    struct.pack_into(
        "<II7iBi",
        header,
        0,
        0x616B3432,
        2,
        dim,
        hidden,
        layers,
        heads,
        kv_heads,
        vocabulary,
        context,
        shared_classifier,
        group_size,
    )
    with destination.open("wb") as output:
        output.write(header)
        for norm in (attention_norm, ffn_norm, final_norm):
            if sys.byteorder != "little":
                norm.byteswap()
            output.write(norm.tobytes())
        output.write(quantize(embeddings, group_size))
        for tensor in (wq, wk, wv, wo, w1, w2, w3):
            output.write(quantize_layers(tensor, layers, group_size))
        if classifier is not None:
            output.write(quantize(classifier, group_size))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    convert(args.source, args.destination)


if __name__ == "__main__":
    main()
