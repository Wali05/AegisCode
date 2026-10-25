import { describe, expect, it } from "vitest";
import { runBenchmark } from "../bench/benchmark";

describe("accuracy benchmark", () => {
  it("stays above the precision / recall floor on the labelled corpus", () => {
    const r = runBenchmark();
    expect(r.cases.length).toBeGreaterThanOrEqual(80);
    expect(r.precision).toBeGreaterThanOrEqual(0.95);
    expect(r.recall).toBeGreaterThanOrEqual(0.95);
  });
});
