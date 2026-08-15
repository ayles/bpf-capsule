// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
var acc = 0;
for (var i = 1; i <= 2000; i++) { acc = (acc + i * 7919) % 1000003; }
var obj = {};
for (var i = 0; i < 200; i++) { obj['k' + i] = i * 3; }
var keys = Object.keys(obj);
for (var i = 0; i < keys.length; i++) { acc = (acc + obj[keys[i]]) % 1000003; }
function mk(n) { return function (x) { return (x * n + 17) % 65521; }; }
var f = mk(31);
for (var i = 0; i < 500; i++) { acc = (acc + f(i)) % 1000003; }
var parts = [];
for (var i = 0; i < 100; i++) { parts.push(i + ':' + (i * i)); }
var s = parts.join(',');
var m = s.match(/(\d+):(\d+)/g);
acc = (acc + s.length + m.length) % 1000003;
// Batch stdin: a line read and a read-all, both deterministic when stdin is
// empty and both exercised in the kernel and the --native run.
var line = readLine();
var rest = read();
console.log('' + acc + '|' + s.length + '|' + m.length + '|' + (line === null) + '|' + rest.length);
