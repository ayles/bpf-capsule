-- A deterministic, CPU-bound workload for comparing the same SQLite in the
-- kernel and natively: bulk insert through a recursive CTE, an index, joins,
-- aggregates, string functions and sorting. Every row it prints is part of the
-- comparison between the two runs.
CREATE TABLE numbers(n INTEGER PRIMARY KEY, square INTEGER, label TEXT);
WITH RECURSIVE r(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM r WHERE i < 60000)
INSERT INTO numbers SELECT i, i * i, 'n-' || i FROM r;
CREATE INDEX numbers_square ON numbers(square % 1009);
SELECT count(*), sum(square) FROM numbers;
SELECT square % 1009 AS bucket, count(*), max(n)
FROM numbers GROUP BY bucket ORDER BY count(*) DESC, bucket LIMIT 5;
SELECT a.n, b.n FROM numbers a JOIN numbers b ON b.n = a.n * 2
WHERE a.n % 997 = 0 ORDER BY a.n DESC LIMIT 5;
SELECT upper(label), length(label), instr(label, '99') FROM numbers
WHERE label LIKE 'n-99%' ORDER BY length(label) DESC, label LIMIT 5;
SELECT avg(square), min(square), max(square) FROM numbers WHERE n % 7 = 3;
SELECT n FROM numbers ORDER BY (n * 7919) % 100003 LIMIT 5;
