import ts from "typescript";
import type { Finding, FileReport, FixSuggestion } from "./types";
import { parseSource } from "./taint/analyzer";
import { diffFindings } from "../baseline";

/**
 * Deterministic quick fixes, each verified by re-running the analysis.
 *
 * A fix is a small source edit for one finding. It only earns the "verified"
 * badge if re-scanning the edited file shows the finding gone *and* nothing
 * new introduced. No model is involved, so fixes are reproducible and work
 * without an API key.
 */

interface Edit {
  start: number;
  end: number;
  text: string;
}

interface Candidate {
  title: string;
  explanation: string;
  edits: Edit[];
}

type Fixer = (ctx: FixContext) => Candidate | null;

interface FixContext {
  sf: ts.SourceFile;
  code: string;
  finding: Finding;
  /** The AST node the finding points at (sink call / assignment). */
  node: ts.Node;
}

const text = (sf: ts.SourceFile, n: ts.Node) => n.getText(sf);

function offsetOf(sf: ts.SourceFile, line: number, column: number): number {
  return sf.getPositionOfLineAndCharacter(line - 1, column - 1);
}

/** The outermost node of `kinds` starting exactly at the finding's location. */
function nodeAt(sf: ts.SourceFile, f: Finding): ts.Node | null {
  const pos = offsetOf(sf, f.location.line, f.location.column);
  let found: ts.Node | null = null;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (n.getStart(sf) === pos && (ts.isCallExpression(n) || ts.isBinaryExpression(n) || ts.isNewExpression(n) || ts.isPropertyAssignment(n))) {
      found = n;
      return;
    }
    if (n.getStart(sf) <= pos && pos < n.getEnd()) ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

function unwrap(e: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) || ts.isAwaitExpression(e)) e = e.expression;
  return e;
}

/** Flattens `"a" + x + "b"` / `` `a${x}b` `` into literal text and expression parts. */
function pieces(sf: ts.SourceFile, e: ts.Expression): Array<{ lit: string } | { expr: ts.Expression }> | null {
  e = unwrap(e);
  if (ts.isStringLiteralLike(e)) return [{ lit: e.text }];
  if (ts.isTemplateExpression(e)) {
    const out: Array<{ lit: string } | { expr: ts.Expression }> = [{ lit: e.head.text }];
    for (const span of e.templateSpans) out.push({ expr: span.expression }, { lit: span.literal.text });
    return out;
  }
  if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = pieces(sf, e.left);
    const r = pieces(sf, e.right);
    return l && r ? [...l, ...r] : null;
  }
  if (ts.isNumericLiteral(e)) return [{ lit: e.text }];
  return [{ expr: e }];
}

// ─── fixers ──────────────────────────────────────────────────────────────────

/** "SELECT … '" + x + "'" → "SELECT … $1", [x] */
const parameteriseSql: Fixer = ({ sf, node }) => {
  if (!ts.isCallExpression(node) || node.arguments.length !== 1) return null;
  const parts = pieces(sf, node.arguments[0]);
  if (!parts || !parts.some((p) => "expr" in p)) return null;
  // Only rewrite when the SQL text is right here; a query built elsewhere needs a fix where it's built.
  if (!parts.some((p) => "lit" in p && /\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES|SET)\b/i.test(p.lit))) return null;
  const callee = text(sf, node.expression);
  const dollar = /pool|pg|postgres|client|sql\b|neon|supabase/i.test(callee);
  let sql = "";
  const params: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if ("lit" in p) {
      sql += p.lit;
      continue;
    }
    // Identifiers (ORDER BY col, table names) can't be bound as parameters — leave those to a human.
    if (/\b(?:ORDER|GROUP)\s+BY\s*$|\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s*$|\b(?:ASC|DESC|LIMIT|OFFSET)\s*$/i.test(sql) && !/\bLIMIT\s*$|\bOFFSET\s*$/i.test(sql)) return null;
    const next = parts[i + 1];
    const after = next && "lit" in next ? next.lit : "";
    let value = text(sf, p.expr);
    // Strip the quotes (and LIKE wildcards) that surrounded the interpolated value.
    const m = /(['"])(%?)$/.exec(sql);
    if (m && after.startsWith(`${m[2]}${m[1]}`)) {
      sql = sql.slice(0, -m[0].length);
      if (next && "lit" in next) next.lit = next.lit.slice(m[2].length + 1);
      if (m[2]) value = `\`%\${${value}}%\``;
    } else if (m && m[2] === "" && /^%/.test(after)) {
      return null;
    }
    params.push(value);
    sql += dollar ? `$${params.length}` : "?";
  }
  return {
    title: "Use a parameterised query",
    explanation: `Values are sent separately from the SQL text (${dollar ? "$1, $2 …" : "? placeholders"}), so they can never change the query's structure.`,
    edits: [{ start: node.arguments[0].getStart(sf), end: node.arguments[0].getEnd(), text: `${JSON.stringify(sql)}, [${params.join(", ")}]` }],
  };
};

/** el.innerHTML = x → el.textContent = x */
const useTextContent: Fixer = ({ sf, node }) => {
  if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return null;
  const left = node.left;
  if (!ts.isPropertyAccessExpression(left) || !/^(?:innerHTML|outerHTML)$/.test(left.name.text)) return null;
  return {
    title: "Write text instead of HTML",
    explanation: "textContent inserts the value as plain text, so markup in it is displayed rather than executed. If you really need HTML, sanitise it with DOMPurify first.",
    edits: [{ start: left.name.getStart(sf), end: left.name.getEnd(), text: "textContent" }],
  };
};

/** fs.readFile(path.join(dir, input)) → path.join(dir, path.basename(input)) */
const basenamePath: Fixer = ({ sf, node, finding, code }) => {
  if (!ts.isCallExpression(node) || !node.arguments[0]) return null;
  if (!/\bimport\s+(?:\*\s+as\s+)?path\b|\brequire\(\s*["'](?:node:)?path["']\s*\)/.test(code)) return null;
  const arg = unwrap(node.arguments[0]);
  const source = finding.trace?.[0]?.snippet.replace(/\s+/g, "") ?? "";
  const tainted = (e: ts.Expression) => {
    const t = text(sf, e).replace(/\s+/g, "");
    return !ts.isStringLiteralLike(e) && (t === source || source.includes(t) || /\breq(?:uest)?\.|\bparams\b|\bquery\b|\bbody\b/.test(t) || (finding.trace ?? []).some((s) => s.label.includes(`\`${t}\``)));
  };
  let targets: ts.Expression[] = [];
  if (ts.isCallExpression(arg) && /^path\.(?:join|resolve)$/.test(text(sf, arg.expression))) targets = arg.arguments.filter(tainted);
  else if (ts.isBinaryExpression(arg) || ts.isTemplateExpression(arg)) targets = (pieces(sf, arg) ?? []).flatMap((p) => ("expr" in p && tainted(p.expr) ? [p.expr] : []));
  // A variable holding a full path can't be fixed here without changing its meaning.
  if (!targets.length) return null;
  return {
    title: "Strip directories from the user-supplied name",
    explanation: "path.basename keeps only the final file name, so ../ sequences can't climb out of the intended folder.",
    edits: targets.map((t) => ({ start: t.getStart(sf), end: t.getEnd(), text: `path.basename(String(${text(sf, t)}))` })),
  };
};

/** Users.findOne({ name: req.body.name }) → { name: String(req.body.name) } */
const castFilterValues: Fixer = ({ sf, node }) => {
  if (!ts.isCallExpression(node) || !node.arguments[0]) return null;
  const filter = unwrap(node.arguments[0]);
  if (!ts.isObjectLiteralExpression(filter)) return null;
  const edits: Edit[] = [];
  for (const p of filter.properties) {
    if (!ts.isPropertyAssignment(p)) continue;
    const v = unwrap(p.initializer);
    if ((ts.isPropertyAccessExpression(v) || ts.isElementAccessExpression(v) || ts.isIdentifier(v)) && !/^String\(/.test(text(sf, v))) {
      edits.push({ start: p.initializer.getStart(sf), end: p.initializer.getEnd(), text: `String(${text(sf, p.initializer)})` });
    }
  }
  if (!edits.length) return null;
  return {
    title: "Cast filter values to strings",
    explanation: "A string can't carry a query operator like {\"$ne\": null}, so the filter only ever matches exact values.",
    edits,
  };
};

/** res.redirect(x) → res.redirect(/^\/(?!\/)[\w\-./?=&%#~]*$/.test(String(x)) ? String(x) : "/") */
const localRedirect: Fixer = ({ sf, node }) => {
  if (!ts.isCallExpression(node) || node.arguments.length !== 1) return null;
  const arg = node.arguments[0];
  const v = `String(${text(sf, unwrap(arg))})`;
  return {
    title: "Only allow same-site paths",
    explanation: "The target must be a path on this site: one leading \"/\" and only URL-safe characters, so \"//evil.example\", \"https://…\" and \"/\\evil\" all fall back to \"/\".",
    edits: [{ start: arg.getStart(sf), end: arg.getEnd(), text: `/^\\/(?!\\/)[\\w\\-./?=&%#~]*$/.test(${v}) ? ${v} : "/"` }],
  };
};

/** rejectUnauthorized: false → true */
const enableTls: Fixer = ({ sf, code, finding }) => {
  const lineStart = offsetOf(sf, finding.location.line, 1);
  const lineEnd = code.indexOf("\n", lineStart) === -1 ? code.length : code.indexOf("\n", lineStart);
  const m = /rejectUnauthorized\s*:\s*false/.exec(code.slice(lineStart, lineEnd));
  if (!m) return null;
  const start = lineStart + m.index;
  return {
    title: "Turn certificate validation back on",
    explanation: "With validation on, a man-in-the-middle can't present a forged certificate. For private CAs, pass them via the `ca` option instead.",
    edits: [{ start, end: start + m[0].length, text: "rejectUnauthorized: true" }],
  };
};

const FIXERS: Record<string, Fixer> = {
  "AEG-TAINT-SQL": parameteriseSql,
  "AEG-TAINT-XSS": useTextContent,
  "AEG-TAINT-PATH": basenamePath,
  "AEG-TAINT-NOSQL": castFilterValues,
  "AEG-TAINT-REDIRECT": localRedirect,
  "AEG-JS-013": enableTls,
};

export function applyEdits(code: string, edits: Edit[]): string {
  let out = code;
  for (const e of [...edits].sort((a, b) => b.start - a.start)) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

/** Line-level before/after for the edited region, for display. */
function hunk(before: string, after: string): FixSuggestion["diff"] {
  const a = before.split("\n");
  const b = after.split("\n");
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length - 1;
  let endB = b.length - 1;
  while (endA >= start && endB >= start && a[endA] === b[endB]) {
    endA--;
    endB--;
  }
  return { line: start + 1, removed: a.slice(start, endA + 1), added: b.slice(start, endB + 1) };
}

/**
 * Suggests and verifies a fix for every finding that has a fixer. `rescan`
 * re-analyses edited code the same way the original was analysed.
 */
export function suggestFixes(report: FileReport, code: string, rescan: (patched: string) => Finding[]): Map<string, FixSuggestion> {
  const out = new Map<string, FixSuggestion>();
  if (report.language !== "javascript" && report.language !== "typescript") return out;
  const sf = parseSource(report.path, code);
  const before = report.findings.filter((f) => f.file === report.path);

  for (const finding of before) {
    const fixer = FIXERS[finding.ruleId];
    if (!fixer || finding.status === "dismissed") continue;
    // A flow that starts in another file can't be re-verified from this file alone.
    if (finding.trace?.some((s) => s.file && s.file !== finding.file)) continue;
    const node = finding.ruleId === "AEG-JS-013" ? sf : nodeAt(sf, finding);
    if (!node) continue;
    let candidate: Candidate | null = null;
    try {
      candidate = fixer({ sf, code, finding, node });
    } catch {
      candidate = null;
    }
    if (!candidate) continue;

    const patched = applyEdits(code, candidate.edits);
    const after = rescan(patched);
    const diff = diffFindings(before, after);
    // The fixers edit within the finding's own line(s), so line numbers don't move.
    const same = (f: Finding) => f.ruleId === finding.ruleId && f.location.line === finding.location.line;
    const stillThere = after.some(same);
    // Findings already on a line before the edit aren't "new" just because the line's text changed.
    const existedAt = new Set(before.map((f) => `${f.ruleId}:${f.location.line}`));
    const introduced = diff.added.filter((f) => !same(f) && f.severity !== "info" && !existedAt.has(`${f.ruleId}:${f.location.line}`));
    const syntaxOk = !ts.transpileModule(patched, { fileName: report.path, reportDiagnostics: true, compilerOptions: { jsx: ts.JsxEmit.Preserve } }).diagnostics?.length;

    out.set(finding.id, {
      title: candidate.title,
      explanation: candidate.explanation,
      diff: hunk(code, patched),
      edits: candidate.edits,
      verified: !stillThere && introduced.length === 0 && syntaxOk,
      note: !syntaxOk
        ? "The edit doesn't parse — needs a manual fix."
        : stillThere
          ? "Re-scan still reports this issue after the edit, so it needs a different fix."
          : introduced.length
            ? `Re-scan found ${introduced.length} new issue${introduced.length === 1 ? "" : "s"} after the edit.`
            : "Re-scanned after the edit: this issue is gone and nothing new was introduced.",
    });
  }
  return out;
}
