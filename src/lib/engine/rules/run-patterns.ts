import type { Finding, Language } from "../types";
import type { SourceViews } from "../lexer";
import { LineIndex } from "../lexer";
import { makeFinding } from "../finding";
import { rulesFor } from "./patterns";

const MAX_MATCHES_PER_RULE = 25;

export function runPatternRules(views: SourceViews, lang: Language, file: string, index: LineIndex): Finding[] {
  const out: Finding[] = [];
  const textIndex = new LineIndex(views.noComments);

  for (const rule of rulesFor(lang)) {
    const haystack = rule.view === "code" ? views.codeOnly : rule.view === "text" ? views.noComments : views.raw;
    const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g";
    const re = new RegExp(rule.pattern.source, flags);
    let count = 0;
    const seenLines = new Set<number>();

    for (const m of haystack.matchAll(re)) {
      if (m.index === undefined) continue;
      // Skip leading whitespace so multi-line patterns anchor on the real token.
      const offset = m.index + (m[0].length - m[0].trimStart().length);
      const start = index.position(offset);
      if (seenLines.has(start.line)) continue;
      const end = index.position(m.index + m[0].length);
      const lineText = textIndex.lineText(start.line);
      if (rule.where && !rule.where(lineText)) continue;

      seenLines.add(start.line);
      out.push(
        makeFinding({
          rule,
          file,
          location: { line: start.line, column: start.column, endLine: end.line, endColumn: end.column },
          snippet: index.lineText(start.line),
          confidence: rule.confidence,
          detector: "pattern",
        })
      );
      if (++count >= MAX_MATCHES_PER_RULE) break;
    }
  }
  return out;
}
