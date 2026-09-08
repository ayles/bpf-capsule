# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
import struct


def ipv4(value):
    return ".".join(str(byte) for byte in value)


def observe(packet):
    length = len(packet)
    if length < 14:
        print(f"TRUNC ethernet len={length}")
        return
    protocol = struct.unpack_from("!H", packet, 12)[0]
    if protocol != 0x0800:
        print(f"ETH type=0x{protocol:04x} len={length}")
        return
    if length < 34:
        print(f"TRUNC ipv4 len={length}")
        return

    ip = 14
    ihl = (packet[ip] & 0x0F) * 4
    transport = ip + ihl
    source = ipv4(packet[ip + 12 : ip + 16])
    destination = ipv4(packet[ip + 16 : ip + 20])
    if ihl < 20 or length < transport:
        print(f"BAD IPv4 {source} > {destination}")
    elif packet[ip + 9] in (6, 17) and length >= transport + 4:
        source_port, destination_port = struct.unpack_from("!HH", packet, transport)
        name = "TCP" if packet[ip + 9] == 6 else "UDP"
        print(f"{name} {source}:{source_port} > {destination}:{destination_port}")
    else:
        print(f"IP {source} > {destination} proto={packet[ip + 9]}")
