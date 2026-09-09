// A deterministic, CPU-bound workload for comparing the same engine in the
// kernel and natively: recursion, integer loops, arrays, strings, objects and
// a little floating point. It prints one checksum so both runs can be compared.

function fib(n) {
  return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

function sieve(limit) {
  const composite = new Uint8Array(limit + 1);
  let count = 0;
  for (let i = 2; i <= limit; i++) {
    if (!composite[i]) {
      count++;
      for (let j = i * i; j <= limit; j += i) composite[j] = 1;
    }
  }
  return count;
}

function sortChecksum(n) {
  const values = [];
  for (let i = 1; i <= n; i++) values.push((i * 7919) % 100003);
  values.sort((a, b) => a - b);
  let sum = 0;
  for (let i = 0; i < n; i += 97) sum += values[i] * (i + 1);
  return sum;
}

function strings(n) {
  const parts = [];
  for (let i = 1; i <= n; i++) parts.push(`${i}:${(i * 31).toString(16)}`);
  const text = parts.join(",").replace(/(\d+):/g, "$1=");
  let total = 0;
  for (const token of text.match(/[0-9a-f]+/g)) total += token.length;
  return total;
}

function objects(n) {
  const map = new Map();
  for (let i = 0; i < n; i++) map.set("key" + (i % 1000), { value: i, square: i * i });
  let total = 0;
  for (const [, entry] of map) total += entry.square % 1000;
  return total;
}

function nbody(steps) {
  let x = 0.0, y = 1.0, vx = 1.0, vy = 0.0;
  for (let i = 0; i < steps; i++) {
    const r2 = x * x + y * y;
    const f = -1.0 / (r2 * Math.sqrt(r2));
    vx += f * x * 0.001;
    vy += f * y * 0.001;
    x += vx * 0.001;
    y += vy * 0.001;
  }
  return Math.floor((x + y) * 1e6);
}

const checksum = fib(27) + sieve(300000) + sortChecksum(100000) + strings(20000) + objects(100000) + nbody(300000);
console.log(`QuickJS benchmark checksum ${checksum}`);
