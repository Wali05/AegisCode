import { writeFileSync } from "node:fs";
import { runBenchmark, toMarkdown } from "./benchmark";

const result = runBenchmark();
writeFileSync("bench/RESULTS.md", toMarkdown(result));
console.log(`precision ${(result.precision * 100).toFixed(1)}%  recall ${(result.recall * 100).toFixed(1)}%  F1 ${(result.f1 * 100).toFixed(1)}%  (${result.cases.length} cases, ${result.ms} ms)`);
for (const c of result.cases) {
  if (c.fn.length) console.log(`  missed      ${c.name}: ${c.fn.join(", ")}`);
  if (c.fp.length) console.log(`  false alarm ${c.name}: ${c.fp.join(", ")}`);
}
