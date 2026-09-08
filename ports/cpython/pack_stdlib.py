#!/usr/bin/env python3
"""Pack CPython's Lib/*.py into the small read-only Capsule import image."""

import pathlib
import struct
import sys


MAGIC = b"BPCPYLIB"
HEADER = struct.Struct("<8sIIII")
ENTRY = struct.Struct("<IIII")
PACKAGE = 1


def module(path: pathlib.Path, root: pathlib.Path) -> tuple[str, bool]:
    relative = path.relative_to(root)
    if relative.name == "__init__.py":
        return ".".join(relative.parent.parts), True
    return ".".join(relative.with_suffix("").parts), False


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: pack_stdlib.py LIB OUTPUT")

    root = pathlib.Path(sys.argv[1]).resolve()
    output = pathlib.Path(sys.argv[2])
    modules = sorted((module(path, root), path) for path in root.rglob("*.py"))
    names = bytearray()
    sources = bytearray()
    records: list[tuple[int, int, int, int]] = []
    data_offset = HEADER.size + ENTRY.size * len(modules)

    for ((name, package), path) in modules:
        encoded_name = name.encode("utf-8")
        source = path.read_bytes()
        name_offset = len(names)
        source_offset = len(sources)
        names.extend(encoded_name)
        names.append(0)
        sources.extend(source)
        sources.append(0)
        records.append((name_offset, source_offset, len(source), PACKAGE if package else 0))

    data_offset += len(names)
    with output.open("wb") as image:
        image.write(HEADER.pack(MAGIC, 1, len(records), len(names), len(sources)))
        for name_offset, source_offset, source_size, flags in records:
            image.write(ENTRY.pack(name_offset, data_offset + source_offset, source_size, flags))
        image.write(names)
        image.write(sources)


if __name__ == "__main__":
    main()
