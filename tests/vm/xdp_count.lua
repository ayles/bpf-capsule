-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-- Test observer: report only UDP datagrams to port 4242, so the event count
-- is exactly what the test sent no matter what else the link carries.
local function be16(offset)
    return packet:byte(offset) * 256 + packet:byte(offset + 1)
end

local length = #packet
if length >= 34 and be16(13) == 0x0800 and packet:byte(24) == 17 then
    local transport = 15 + (packet:byte(15) & 0x0f) * 4
    if length >= transport + 3 and be16(transport + 2) == 4242 then
        print("UDP 4242 len=" .. length)
    end
end
