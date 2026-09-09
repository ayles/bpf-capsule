# A deterministic, CPU-bound workload for comparing the same interpreter in
# the kernel and natively: recursion, integer loops, lists, strings, dicts,
# a little floating point and a few built-in modules. It prints one checksum
# so both runs can be compared.
import hashlib
import json
import zlib


def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)


def sieve(limit):
    composite = bytearray(limit + 1)
    count = 0
    for i in range(2, limit + 1):
        if not composite[i]:
            count += 1
            composite[i * i :: i] = b"\x01" * len(range(i * i, limit + 1, i))
    return count


def sort_checksum(n):
    values = sorted((i * 7919) % 100003 for i in range(1, n + 1))
    return sum(values[i] * (i + 1) for i in range(0, n, 97))


def strings(n):
    text = ",".join(f"{i}:{i * 31:x}" for i in range(1, n + 1))
    replaced = text.replace(":", "=")
    return sum(len(token) for token in replaced.split(","))


def objects(n):
    table = {}
    for i in range(n):
        table[f"key{i % 1000}"] = {"value": i, "square": i * i}
    return sum(entry["square"] % 1000 for entry in table.values())


def nbody(steps):
    x, y, vx, vy = 0.0, 1.0, 1.0, 0.0
    for _ in range(steps):
        r2 = x * x + y * y
        f = -1.0 / (r2 * r2**0.5)
        vx += f * x * 0.001
        vy += f * y * 0.001
        x += vx * 0.001
        y += vy * 0.001
    return int((x + y) * 1e6)


def modules(n):
    payload = json.dumps({"values": list(range(n))}).encode()
    compressed = zlib.compress(payload)
    digest = hashlib.sha256(compressed).hexdigest()
    return len(compressed) + int(digest[:8], 16) % 100000


checksum = fib(24) + sieve(300000) + sort_checksum(100000) + strings(20000) + objects(100000) + nbody(300000) + modules(50000)
print(f"Python benchmark checksum {checksum}")
