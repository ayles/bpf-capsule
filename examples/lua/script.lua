-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
local checksum = 0

for value = 1, 2000 do
    checksum = (checksum + value * 17) % 1000003
end

-- Batch stdin: one line followed by all remaining input.
local first = io.read()
local rest = io.read("a")
local floats_work = tonumber("12.5") == 12.5 and 1.5 * 2 == 3 and 0x1.8p+1 == 3
    and tostring(12.5) == "12.5" and string.format("%.2f", 1.25) == "1.25"

print("Lua checksum", checksum, first == nil, #rest, floats_work)
