# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Import source modules during initialization, which may use continuations.
# Packet processing must finish in one invocation, including on its first call.
import decimal
import hashlib
import json
import sqlite3
import sys
import zlib

assert "colorsys" not in sys.modules, "colorsys imported before packet processing"


def observe(packet):
    if len(packet) < 42 or packet[12:14] != b"\x08\x00":
        return
    ip = 14
    transport = ip + (packet[ip] & 0x0F) * 4
    if packet[ip + 9] != 17 or len(packet) < transport + 4:
        return
    source = int.from_bytes(packet[transport : transport + 2], "big")
    destination = int.from_bytes(packet[transport + 2 : transport + 4], "big")
    if destination == 4243:
        # Built-in imports exercise shared runtime state while the other
        # modules use each interpreter's private state.
        import sys
        import _thread

        if packet[transport + 8 : transport + 12] == b"test":
            # Only the simultaneous test-run senders trigger this cold import.
            # Keep it small enough to compile on the packet path.
            import colorsys

            assert colorsys.rgb_to_hsv(1, 0, 0) == (0, 1, 1), "cold colorsys import"

        with decimal.localcontext() as context:
            context.prec = 20
            assert decimal.Decimal("1.25") * 8 == 10, "decimal multiplication"
        assert len(hashlib.sha256(packet).digest()) == 32, "sha256 digest"
        assert json.loads(json.dumps([source, destination])) == [source, 4243], "json round trip"
        assert zlib.decompress(zlib.compress(packet)) == packet, "zlib round trip"
        with sqlite3.connect(":memory:") as database:
            assert database.execute("select ? + 1", (destination,)).fetchone() == (4244,), "sqlite query"
        # Do not inspect other interpreters' frames: _current_frames() also
        # corrupts memory in native CPython 3.14.7 with isolated interpreters.
        assert sys._getframe().f_code.co_name == "observe", "current frame"
        assert isinstance(_thread.get_ident(), int), "thread identity"
        print(f"UDP {source} > {destination}")
