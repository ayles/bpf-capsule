-- A deterministic, CPU-bound workload for comparing the same interpreter in
-- the kernel and natively: recursion, integer loops, tables, strings and a
-- little floating point. It prints one checksum so both runs can be compared.

local function fib(n)
  if n < 2 then return n end
  return fib(n - 1) + fib(n - 2)
end

local function sieve(limit)
  local composite, count = {}, 0
  for i = 2, limit do
    if not composite[i] then
      count = count + 1
      for j = i * i, limit, i do composite[j] = true end
    end
  end
  return count
end

local function sort_checksum(n)
  local values = {}
  for i = 1, n do values[i] = (i * 7919) % 100003 end
  table.sort(values)
  local sum = 0
  for i = 1, n, 97 do sum = sum + values[i] * i end
  return sum
end

local function strings(n)
  local parts = {}
  for i = 1, n do parts[#parts + 1] = string.format("%d:%x", i, i * 31) end
  local text = table.concat(parts, ",")
  local replaced = text:gsub("(%d+):", "%1=")
  local total = 0
  for token in replaced:gmatch("%x+") do total = total + #token end
  return total
end

local function nbody(steps)
  local x, y, vx, vy = 0.0, 1.0, 1.0, 0.0
  for _ = 1, steps do
    local r2 = x * x + y * y
    local r = math.sqrt(r2)
    local f = -1.0 / (r2 * r)
    vx, vy = vx + f * x * 0.001, vy + f * y * 0.001
    x, y = x + vx * 0.001, y + vy * 0.001
  end
  return math.floor((x + y) * 1e6)
end

local checksum = fib(27) + sieve(300000) + sort_checksum(100000) + strings(20000) + nbody(300000)
print(string.format("Lua benchmark checksum %d", checksum))
