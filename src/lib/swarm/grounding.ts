import type { Claim } from "./schemas";

export interface GroundingResult {
  grounded: boolean;
  relocated: boolean;
  line_start: number;
  line_end: number;
  note: string;
}

const norm = (s: string) => s.replace(/\s+/g, " ").trim();

/**
 * Anti-hallucination gate. A claim survives only if its quoted evidence
 * actually exists in the file. Claims with correct evidence but wrong line
 * numbers are relocated; claims whose evidence cannot be found are rejected
 * before they ever reach the Defender or the Judge.
 */
export function groundClaim(claim: Claim, code: string): GroundingResult {
  const lines = code.split("\n");
  const total = lines.length;
  const evidenceLines = claim.evidence
    .split("\n")
    .map(norm)
    .filter((l) => l.length >= 4 && !/^[{}()[\];,]+$/.test(l) && !/^\.\.\.|…$/.test(l));

  if (!evidenceLines.length) {
    return { grounded: false, relocated: false, line_start: claim.line_start, line_end: claim.line_end, note: "No quotable evidence was provided." };
  }

  const normLines = lines.map(norm);
  const findLine = (needle: string, near: number): number => {
    let best = -1;
    let bestDist = Infinity;
    normLines.forEach((l, i) => {
      if (l.includes(needle)) {
        const d = Math.abs(i + 1 - near);
        if (d < bestDist) {
          best = i + 1;
          bestDist = d;
        }
      }
    });
    return best;
  };

  const anchor = evidenceLines.reduce((a, b) => (b.length > a.length ? b : a));
  // Long single lines are sometimes quoted partially; accept a 40-char core.
  const probes = [anchor, anchor.length > 60 ? anchor.slice(0, 40) : null].filter(Boolean) as string[];
  let found = -1;
  for (const p of probes) {
    found = findLine(p, claim.line_start);
    if (found > 0) break;
  }

  if (found < 0) {
    return { grounded: false, relocated: false, line_start: claim.line_start, line_end: claim.line_end, note: "Quoted evidence does not appear in the file — likely hallucinated." };
  }

  const inRange = claim.line_start >= 1 && claim.line_end <= total && found >= claim.line_start - 3 && found <= claim.line_end + 3;
  if (inRange) {
    return { grounded: true, relocated: false, line_start: claim.line_start, line_end: Math.max(claim.line_start, claim.line_end), note: "Evidence verified at the cited lines." };
  }
  const span = Math.max(0, Math.min(claim.line_end - claim.line_start, 10));
  return {
    grounded: true,
    relocated: true,
    line_start: found,
    line_end: Math.min(total, found + span),
    note: `Evidence found at line ${found} (model cited ${claim.line_start}); location corrected.`,
  };
}
