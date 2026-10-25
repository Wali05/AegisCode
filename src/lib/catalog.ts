import type { Detector, FindingCategory, Language, Severity } from "./engine/types";
import { PATTERN_RULES } from "./engine/rules/patterns";
import { SECRET_RULES } from "./engine/secrets";
import { SINKS } from "./engine/taint/model";
import { QUALITY_RULES } from "./engine/quality";
import { PACKAGE_RULE_LIST } from "./deps/packages";

export interface CatalogRule {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  cwe: string[];
  owasp?: string;
  languages: Language[] | "*";
  detector: Detector;
  description: string;
  remediation: string;
}

/** Every rule the engine can emit, flattened for documentation and stats. */
export function ruleCatalog(): CatalogRule[] {
  const sinks = new Map<string, CatalogRule>();
  for (const s of SINKS) {
    const existing = sinks.get(s.id);
    if (existing) continue;
    sinks.set(s.id, {
      id: s.id,
      title: s.title,
      severity: s.severity,
      category: s.category,
      cwe: s.cwe,
      owasp: s.owasp,
      languages: ["javascript", "typescript", "python", "php"],
      detector: "taint",
      description: s.description,
      remediation: s.remediation,
    });
  }
  const strip = ({ id, title, severity, category, cwe, owasp, languages, detector, description, remediation }: CatalogRule): CatalogRule => ({ id, title, severity, category, cwe, owasp, languages, detector, description, remediation });
  return [
    ...sinks.values(),
    ...PATTERN_RULES.map(strip),
    ...SECRET_RULES.map(strip),
    ...PACKAGE_RULE_LIST.map((r) => strip(r as CatalogRule)),
    ...Object.values(QUALITY_RULES).map((q) => strip({ ...q, languages: ["javascript", "typescript"], detector: "metric" })),
  ];
}

export function catalogStats() {
  const rules = ruleCatalog();
  const cwes = new Set(rules.flatMap((r) => r.cwe));
  const languages = new Set(rules.flatMap((r) => (r.languages === "*" ? [] : r.languages)));
  return { rules: rules.length, cwes: cwes.size, languages: languages.size };
}
