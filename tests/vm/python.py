# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
import array
import binascii
import bz2
import cmath
import decimal
import errno
import grp
import hashlib
import json
import lzma
import math
import os
import pickle
import pwd
import random
import sqlite3
import statistics
import struct
import time
import unicodedata
import xml.etree.ElementTree as ET
import zlib
from compression import zstd


values = json.loads('{"values":[3,1,4,1,5]}')["values"]
packed = struct.pack("!5I", *values)
for codec in (zlib, bz2, lzma, zstd):
    assert codec.decompress(codec.compress(packed)) == packed
with sqlite3.connect(":memory:") as database:
    database.execute("create table samples(value real)")
    database.executemany("insert into samples values (?)", [(value,) for value in values])
    assert database.execute("select sum(value) / count(*) from samples").fetchone() == (2.8,)
root = ET.fromstring("<root><value>7</value></root>")
scaled = decimal.Decimal(root.findtext("value")) * decimal.Decimal("1.25")
assert array.array("I", values).tolist() == values
assert binascii.crc32(b"capsule") == 0xC268A183
assert math.isclose(statistics.fmean(values), 2.8)
assert cmath.sqrt(-4).imag == 2.0
assert pickle.loads(pickle.dumps(values)) == values
assert 0.0 <= random.random() < 1.0
assert time.time() > 1_600_000_000
assert time.monotonic() > 0
assert unicodedata.name("A") == "LATIN CAPITAL LETTER A"
for codec, text in (("gb18030", "你好"), ("shift_jis", "日本語"), ("big5", "中文")):
    assert text.encode(codec).decode(codec) == text
try:
    pwd.getpwnam("capsule-user")
except KeyError:
    pass
else:
    raise AssertionError("the embedding unexpectedly has a password database")
try:
    grp.getgrnam("capsule-group")
except KeyError:
    pass
else:
    raise AssertionError("the embedding unexpectedly has a group database")
for mode, error in (("r", errno.ENOENT), ("w", errno.EROFS)):
    try:
        open("missing", mode)
    except OSError as exception:
        assert exception.errno == error
    else:
        raise AssertionError("filesystem access unexpectedly succeeded")
try:
    os.getcwd()
except OSError as exception:
    assert exception.errno == errno.ENOSYS
else:
    raise AssertionError("the embedding has no working directory")
print("CPython", hashlib.sha256(packed).hexdigest()[:16], scaled)
