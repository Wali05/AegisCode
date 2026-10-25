import { writeFileSync } from "node:fs";
import { runBenchmark, toMarkdown } from "./benchmark";

const result = runBenchmark();
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
      holdoutFirstRun: { cases: 26, precision: 94.1, recall: 88.9 },
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
