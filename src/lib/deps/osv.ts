import type { Finding, Severity } from "../engine/types";
import { makeFinding } from "../engine/finding";
import { OWASP } from "../engine/rules/patterns";
import { mapLimit } from "../util/concurrency";
import type { Dependency } from "./manifests";

const OSV_API = "https://api.osv.dev/v1";
const MAX_DETAILS = 60;

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
  }>;
}

// ─── CVSS v3.x base score ────────────────────────────────────────────────────

const CVSS3 = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

const roundUp = (x: number) => Math.ceil(x * 10 - 1e-9) / 10;

/** Computes the CVSS v3.0/3.1 base score from a vector string. Returns null for other versions. */
export function cvss3Score(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = Object.fromEntries(vector.split("/").slice(1).map((kv) => kv.split(":"))) as Record<string, string>;
  const changed = m.S === "C";
  const av = CVSS3.AV[m.AV as keyof typeof CVSS3.AV];
  const ac = CVSS3.AC[m.AC as keyof typeof CVSS3.AC];
  const ui = CVSS3.UI[m.UI as keyof typeof CVSS3.UI];
  const pr = m.PR === "N" ? 0.85 : m.PR === "L" ? (changed ? 0.68 : 0.62) : m.PR === "H" ? (changed ? 0.5 : 0.27) : undefined;
  const [c, i, a] = ["C", "I", "A"].map((k) => CVSS3.CIA[m[k] as keyof typeof CVSS3.CIA]);
  if ([av, ac, ui, pr, c, i, a].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr! * ui;
  if (impact <= 0) return 0;
  return roundUp(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function osvSeverity(v: OsvVuln): { severity: Severity; score: number | null } {
  for (const s of v.severity ?? []) {
    const score = cvss3Score(s.score);
    if (score !== null) return { severity: severityFromScore(score), score };
  }
  const label = v.database_specific?.severity?.toUpperCase();
  const map: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };
  return { severity: (label && map[label]) || "medium", score: null };
}

function fixedVersion(v: OsvVuln, dep: Dependency): string | null {
  for (const aff of v.affected ?? []) {
    if (aff.package && aff.package.name.toLowerCase() !== dep.name.toLowerCase()) continue;
    for (const r of aff.ranges ?? []) {
      const fixed = r.events.map((e) => e.fixed).filter(Boolean) as string[];
      if (fixed.length) return fixed[fixed.length - 1];
    }
  }
  return null;
}

async function post<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: signal ?? AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`OSV ${res.status}`);
  return (await res.json()) as T;
}

export interface DependencyScan {
  scanned: number;
  vulnerable: number;
  findings: Finding[];
}

/** Queries OSV.dev for every dependency and turns advisories into findings. */
export async function scanDependencies(deps: Dependency[], signal?: AbortSignal): Promise<DependencyScan> {
  const unique = [...new Map(deps.map((d) => [`${d.ecosystem}:${d.name}@${d.version}`, d])).values()];
  if (!unique.length) return { scanned: 0, vulnerable: 0, findings: [] };

  const hits: Array<{ dep: Dependency; ids: string[] }> = [];
  for (let i = 0; i < unique.length; i += 500) {
    const chunk = unique.slice(i, i + 500);
    const res = await post<{ results: Array<{ vulns?: Array<{ id: string }> }> }>(
      `${OSV_API}/querybatch`,
      { queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) },
      signal
    );
    res.results.forEach((r, j) => {
      if (r.vulns?.length) hits.push({ dep: chunk[j], ids: r.vulns.map((v) => v.id) });
    });
  }

  const pairs = hits.flatMap((h) => h.ids.map((id) => ({ dep: h.dep, id }))).slice(0, MAX_DETAILS);
  const details = new Map<string, OsvVuln>();
  await mapLimit([...new Set(pairs.map((p) => p.id))], 8, async (id) => {
    try {
      const res = await fetch(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { signal: signal ?? AbortSignal.timeout(10_000) });
      if (res.ok) details.set(id, (await res.json()) as OsvVuln);
    } catch {
      /* a missing advisory body only costs us its summary */
    }
  });

  const findings = pairs.map(({ dep, id }) => {
    const v = details.get(id) ?? { id };
    const { severity, score } = osvSeverity(v);
    const fixed = fixedVersion(v, dep);
    const cve = v.aliases?.find((a) => a.startsWith("CVE-"));
    const summary = v.summary ?? v.details?.split("\n")[0] ?? "Known vulnerability";
    const f = makeFinding({
      rule: {
        id,
        title: `${dep.name}@${dep.version}: ${summary}`,
        severity,
        category: "dependency",
        cwe: v.database_specific?.cwe_ids?.length ? v.database_specific.cwe_ids : ["CWE-1395"],
        owasp: OWASP.supplyChain,
        description: `${summary}${cve ? ` (${cve})` : ""}${score !== null ? ` · CVSS ${score.toFixed(1)}` : ""}${dep.exact ? "" : " · version inferred from the lowest version allowed by the manifest range"}.`,
        remediation: fixed ? `Upgrade ${dep.name} to ${fixed} or later.` : `No fixed release is listed yet — evaluate an alternative package or mitigate the vulnerable code path.`,
      },
      file: dep.manifest,
      location: { line: dep.line ?? 1, column: 1, endLine: dep.line ?? 1, endColumn: 1 },
      snippet: `${dep.name}@${dep.version}`,
      confidence: dep.exact ? 0.95 : 0.7,
      detector: "osv",
    });
    return f;
  });

  return { scanned: unique.length, vulnerable: hits.length, findings };
}
