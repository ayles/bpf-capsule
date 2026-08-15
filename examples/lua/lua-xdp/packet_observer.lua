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
    print("TRUNC ethernet len=" .. length)
elseif be16(13) ~= 0x0800 then
    print(string.format("ETH type=0x%04x len=%d", be16(13), length))
elseif length < 34 then
    print("TRUNC ipv4 len=" .. length)
else
    local ip = 15
    local ihl = (byte(ip) & 0x0f) * 4
    local protocol = byte(ip + 9)
    local source = ipv4(ip + 12)
    local destination = ipv4(ip + 16)
    local transport = ip + ihl

    if ihl < 20 or length < transport - 1 then
        print("BAD IPv4 " .. source .. " > " .. destination)
    elseif protocol == 6 and length >= transport + 3 then
        print(string.format("TCP %s:%d > %s:%d",
            source, be16(transport), destination, be16(transport + 2)))
    elseif protocol == 17 and length >= transport + 3 then
        print(string.format("UDP %s:%d > %s:%d",
            source, be16(transport), destination, be16(transport + 2)))
    else
        print(string.format("IP %s > %s proto=%d",
            source, destination, protocol))
    end
end

-- This observer never makes a traffic decision. The native XDP wrapper also
-- returns XDP_PASS on Lua errors, Capsule exhaustion, or a busy singleton.
return 1
