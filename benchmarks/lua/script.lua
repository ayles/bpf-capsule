-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-- Keep this workload stable: correctness coverage belongs in tests/lua/script.lua.
local checksum = 0

for value = 1, 2000 do
    checksum = (checksum + value * 17) % 1000003
end

local first = io.read()
local rest = io.read("a")

print("Lua checksum", checksum, first == nil, #rest)
