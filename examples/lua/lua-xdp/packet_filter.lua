-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
local function byte(index)
    return packet:byte(index)
end

local function be16(offset)
    return byte(offset) * 256 + byte(offset + 1)
end

local function ipv4(offset)
    local a, b, c, d = packet:sub(offset, offset + 3):byte(1, 4)
    return string.format("%d.%d.%d.%d", a, b, c, d)
end

local length = #packet
if length < 14 then
    print("DROP truncated-ethernet len", length)
    return 0
end

local ether_type = be16(13)
if ether_type ~= 0x0800 or length < 34 then
    print(string.format("DROP ethertype=0x%04x len=%d", ether_type, length))
    return 0
end

local ip = 15
local ihl = (byte(ip) & 0x0f) * 4
local protocol = byte(ip + 9)
local source = ipv4(ip + 12)
local destination = ipv4(ip + 16)

local transport = ip + ihl
if ihl < 20 or length < transport - 1 then
    print("DROP malformed-ip len", length)
    return 0
end

if protocol ~= 6 or length < transport + 19 then
    print(string.format("DROP %s > %s proto=%d len=%d",
        source, destination, protocol, length))
    return 0
end

local tcp = transport
local source_port = be16(tcp)
local destination_port = be16(tcp + 2)
local flags = byte(tcp + 13)
local syn = (flags & 0x02) ~= 0 and " syn" or ""
local decision = destination_port == 443 and 1 or 0
local action = decision == 1 and "PASS" or "DROP"

print(string.format("%s %s:%d > %s:%d tcp%s len=%d",
    action, source, source_port, destination, destination_port, syn, length))
return decision
