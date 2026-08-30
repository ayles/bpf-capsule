-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
local checksum = 0

for value = 1, 2000 do
    checksum = (checksum + value * 17) % 1000003
end

-- Batch stdin: one line followed by all remaining input.
local first = io.read()
local rest = io.read("a")

print("Lua checksum", checksum, first == nil, #rest)
