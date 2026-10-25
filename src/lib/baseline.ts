import type { Finding } from "./engine/types";

/**
 * Compares two sets of findings to separate what a change introduced from
 * what was already there. Line numbers shift whenever code above a finding
 * changes, so findings are matched on rule + file + the normalised text of the
 * offending line, counting duplicates (two identical issues in one file are
 * two issues).
 */

export interface Comparison {
  /** Present now, absent before — what the change introduced. */
  added: Finding[];
  /** Present before, absent now — what the change fixed. */
  fixed: Finding[];
  /** Present on both sides. */
  existing: Finding[];
}

export function baselineKey(f: Pick<Finding, "ruleId" | "file" | "snippet">): string {
  return `${f.ruleId}|${f.file}|${f.snippet.replace(/\s+/g, " ").trim()}`;
}

const isOpen = (f: Finding) => f.status !== "dismissed";

export function diffFindings(before: Finding[], after: Finding[]): Comparison {
  const remaining = new Map<string, Finding[]>();
  for (const f of before.filter(isOpen)) remaining.set(baselineKey(f), [...(remaining.get(baselineKey(f)) ?? []), f]);

  const added: Finding[] = [];
  const existing: Finding[] = [];
  for (const f of after.filter(isOpen)) {
    const bucket = remaining.get(baselineKey(f));
    if (bucket?.length) {
      bucket.shift();
      existing.push(f);
    } else {
      added.push(f);
    }
  }
  return { added, fixed: [...remaining.values()].flat(), existing };
}

/** The serialisable baseline file written by `aegis scan --write-baseline`. */
export interface BaselineFile {
  version: 1;
  createdAt: string;
  findings: Array<Pick<Finding, "ruleId" | "file" | "snippet" | "title" | "severity">>;
}

export function toBaseline(findings: Finding[]): BaselineFile {
  return {
    version: 1,
    createdAt: new Date().toISOString(),
    findings: findings.filter(isOpen).map(({ ruleId, file, snippet, title, severity }) => ({ ruleId, file, snippet, title, severity })),
  };
}
