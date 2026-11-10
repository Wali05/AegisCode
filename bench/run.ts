import { writeFileSync } from "node:fs";
import { ROUNDS, runBenchmark, toMarkdown } from "./benchmark";

const result = runBenchmark();
const latest = ROUNDS[ROUNDS.length - 1];
if (ROUNDS.reduce((n, r) => n + r.cases, 0) !== result.cases.length) {
  throw new Error(`bench/benchmark.ts ROUNDS accounts for ${ROUNDS.reduce((n, r) => n + r.cases, 0)} cases but ${result.cases.length} were found: record the new round and its first-run score.`);
}
writeFileSync("bench/RESULTS.md", toMarkdown(result));
// A small summary the website reads, so the numbers it shows always come from the last run.
writeFileSync(
  "src/lib/bench-summary.json",
  JSON.stringify(
    {
      cases: result.cases.length,
      vulnerable: result.cases.filter((c) => c.expected.length).length,
      precision: Math.round(result.precision * 1000) / 10,
      recall: Math.round(result.recall * 1000) / 10,
      // The most recent round's score before any of its misses were fixed.
      latestFirstRun: { cases: latest.cases, precision: latest.precision, recall: latest.recall },
    },
    null,
    2
  ) + "\n"
);
console.log(`precision ${(result.precision * 100).toFixed(1)}%  recall ${(result.recall * 100).toFixed(1)}%  F1 ${(result.f1 * 100).toFixed(1)}%  (${result.cases.length} cases, ${result.ms} ms)`);
for (const c of result.cases) {
  if (c.fn.length) console.log(`  missed      ${c.name}: ${c.fn.join(", ")}`);
  if (c.fp.length) console.log(`  false alarm ${c.name}: ${c.fp.join(", ")}`);
}
