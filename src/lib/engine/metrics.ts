import ts from "typescript";
import type { FileMetrics, FunctionMetric, Language } from "./types";
import type { SourceViews } from "./lexer";
import { LineIndex } from "./lexer";

// ─── JavaScript / TypeScript: exact metrics from the AST ─────────────────────

function isFunctionLike(n: ts.Node): n is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(n) ||
    ts.isFunctionExpression(n) ||
    ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n) ||
    ts.isConstructorDeclaration(n) ||
    ts.isGetAccessor(n) ||
    ts.isSetAccessor(n)
  );
}

function decisionWeight(n: ts.Node): number {
  switch (n.kind) {
    case ts.SyntaxKind.IfStatement:
    case ts.SyntaxKind.ConditionalExpression:
    case ts.SyntaxKind.ForStatement:
    case ts.SyntaxKind.ForInStatement:
    case ts.SyntaxKind.ForOfStatement:
    case ts.SyntaxKind.WhileStatement:
    case ts.SyntaxKind.DoStatement:
    case ts.SyntaxKind.CaseClause:
    case ts.SyntaxKind.CatchClause:
      return 1;
    case ts.SyntaxKind.BinaryExpression: {
      const op = (n as ts.BinaryExpression).operatorToken.kind;
      return op === ts.SyntaxKind.AmpersandAmpersandToken || op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken ? 1 : 0;
    }
    default:
      return 0;
  }
}

function isNestingNode(n: ts.Node): boolean {
  return (
    ts.isIfStatement(n) ||
    ts.isForStatement(n) ||
    ts.isForInStatement(n) ||
    ts.isForOfStatement(n) ||
    ts.isWhileStatement(n) ||
    ts.isDoStatement(n) ||
    ts.isSwitchStatement(n) ||
    ts.isTryStatement(n)
  );
}

export function functionName(fn: ts.FunctionLikeDeclaration, sf: ts.SourceFile): string {
  if (fn.name && (ts.isIdentifier(fn.name) || ts.isStringLiteral(fn.name) || ts.isPrivateIdentifier(fn.name))) return fn.name.text;
  if (ts.isConstructorDeclaration(fn)) return "constructor";
  const p = fn.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  if (p && ts.isPropertyAssignment(p)) return p.name.getText(sf);
  if (p && ts.isPropertyDeclaration(p)) return p.name.getText(sf);
  if (p && ts.isCallExpression(p)) {
    const callee = p.expression.getText(sf).replace(/\s+/g, "");
    return `${callee.length > 28 ? callee.slice(0, 28) + "…" : callee}(callback)`;
  }
  if (p && ts.isExportAssignment(p)) return "default";
  return "<anonymous>";
}

function astMetrics(sf: ts.SourceFile): { functions: FunctionMetric[]; complexity: number } {
  const functions: FunctionMetric[] = [];
  let fileDecisions = 0;
  const lineOf = (pos: number) => sf.getLineAndCharacterOfPosition(pos).line + 1;

  const measure = (fn: ts.FunctionLikeDeclaration) => {
    let decisions = 0;
    let maxNesting = 0;
    const walk = (n: ts.Node, depth: number) => {
      if (n !== fn && isFunctionLike(n)) return; // nested functions are measured separately
      decisions += decisionWeight(n);
      const d = isNestingNode(n) && !(ts.isIfStatement(n) && ts.isIfStatement(n.parent) && n.parent.elseStatement === n) ? depth + 1 : depth;
      maxNesting = Math.max(maxNesting, d);
      ts.forEachChild(n, (c) => walk(c, d));
    };
    if (fn.body) walk(fn.body, 0);
    const line = lineOf(fn.getStart(sf));
    const endLine = lineOf(fn.getEnd());
    // Skip trivial one-line arrows (`x => x.id`) — they drown out the interesting functions.
    if (ts.isArrowFunction(fn) && endLine === line && decisions === 0) return;
    functions.push({
      name: functionName(fn, sf),
      line,
      endLine,
      loc: endLine - line + 1,
      complexity: decisions + 1,
      maxNesting,
      params: fn.parameters.length,
    });
  };

  const visit = (n: ts.Node) => {
    fileDecisions += decisionWeight(n);
    if (isFunctionLike(n)) measure(n);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return { functions, complexity: fileDecisions + 1 };
}

function astHalstead(sf: ts.SourceFile): number {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, true, sf.languageVariant, sf.text);
  const operators = new Map<string, number>();
  const operands = new Map<string, number>();
  let kind = scanner.scan();
  while (kind !== ts.SyntaxKind.EndOfFileToken) {
    const text = scanner.getTokenText();
    const bucket =
      kind === ts.SyntaxKind.Identifier ||
      kind === ts.SyntaxKind.NumericLiteral ||
      kind === ts.SyntaxKind.StringLiteral ||
      kind === ts.SyntaxKind.NoSubstitutionTemplateLiteral
        ? operands
        : operators;
    bucket.set(text, (bucket.get(text) ?? 0) + 1);
    kind = scanner.scan();
  }
  return volume(operators, operands);
}

function volume(operators: Map<string, number>, operands: Map<string, number>): number {
  const N = [...operators.values(), ...operands.values()].reduce((a, b) => a + b, 0);
  const n = operators.size + operands.size;
  return n > 1 ? N * Math.log2(n) : 0;
}

// ─── Other languages: lexical approximation ──────────────────────────────────

const DECISION_RE: Partial<Record<Language, RegExp>> = {
  python: /\b(?:if|elif|for|while|except|and|or|case)\b|\bif\b.*\belse\b/g,
  ruby: /\b(?:if|elsif|unless|for|while|until|when|rescue|and|or)\b|&&|\|\|/g,
  shell: /\b(?:if|elif|for|while|until|case)\b|&&|\|\|/g,
};
const DEFAULT_DECISIONS = /\b(?:if|for|while|case|catch|foreach|elseif|except)\b|&&|\|\||\?\?|\?(?=[^:?.]*:)/g;
const NOT_FUNCTIONS = new Set(["if", "for", "while", "switch", "catch", "return", "sizeof", "foreach", "elseif", "using", "lock", "fixed", "new", "else", "do"]);

function lexicalFunctions(views: SourceViews, lang: Language, index: LineIndex): FunctionMetric[] {
  const code = views.codeOnly;
  const decisions = DECISION_RE[lang] ?? DEFAULT_DECISIONS;
  const out: FunctionMetric[] = [];

  const countIn = (from: number, to: number) => {
    const slice = code.slice(from, to);
    return (slice.match(new RegExp(decisions.source, "g")) ?? []).length;
  };

  if (lang === "python" || lang === "ruby") {
    const header = lang === "python" ? /^([ \t]*)(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(([^)]*)\)/gm : /^([ \t]*)def[ \t]+([\w.?!]+)(?:[ \t]*\(([^)]*)\))?/gm;
    const codeLines = code.split("\n");
    for (const m of code.matchAll(header)) {
      const indent = m[1].length;
      const start = m.index!;
      const startLine = index.position(start).line;
      let endLine = startLine;
      for (let l = startLine + 1; l <= codeLines.length; l++) {
        const text = codeLines[l - 1];
        if (!text.trim()) continue;
        const ind = text.length - text.trimStart().length;
        if (lang === "ruby") {
          endLine = l;
          if (ind === indent && /^\s*end\b/.test(text)) break;
        } else {
          if (ind <= indent) break;
          endLine = l;
        }
      }
      const params = m[3]?.trim() ? m[3].split(",").filter((p) => !/^\s*(self|cls)\s*$/.test(p)).length : 0;
      const endOffset = index.lineStart(endLine + 1);
      out.push({ name: m[2], line: startLine, endLine, loc: endLine - startLine + 1, complexity: countIn(start, endOffset) + 1, maxNesting: 0, params });
    }
    return out;
  }

  // Brace languages: find a signature, then match braces on the masked view.
  const signature =
    lang === "go"
      ? /\bfunc[ \t]+(?:\([^)]*\)[ \t]*)?(\w+)[ \t]*(?:\[[^\]]*\])?\(([^)]*)\)[^{\n]*\{/g
      : lang === "rust"
        ? /\bfn[ \t]+(\w+)[ \t]*(?:<[^>]*>)?\(([^)]*)\)[^{;\n]*\{/g
        : lang === "php"
          ? /\bfunction[ \t]+&?(\w+)[ \t]*\(([^)]*)\)[^{;\n]*\{/g
          : lang === "shell"
            ? /^[ \t]*(?:function[ \t]+)?(\w+)[ \t]*\(\)[ \t]*\{/gm
            : /^[ \t]*(?:[\w<>[\],.?*&:]+[ \t]+)+\**(\w+)[ \t]*\(([^)]*)\)[ \t]*(?:const[ \t]*)?(?:throws[ \t]+[\w.,\s]+)?\{/gm;

  for (const m of code.matchAll(signature)) {
    const name = m[1];
    if (NOT_FUNCTIONS.has(name)) continue;
    const open = m.index! + m[0].length - 1;
    let depth = 0;
    let close = code.length;
    let nesting = 0;
    let maxNesting = 0;
    for (let i = open; i < code.length; i++) {
      if (code[i] === "{") {
        depth++;
        nesting = depth - 1;
        maxNesting = Math.max(maxNesting, nesting);
      } else if (code[i] === "}") {
        depth--;
        if (depth === 0) {
          close = i;
          break;
        }
      }
    }
    const line = index.position(m.index!).line;
    const endLine = index.position(close).line;
    const params = m[2]?.trim() ? m[2].split(",").length : 0;
    out.push({ name, line, endLine, loc: endLine - line + 1, complexity: countIn(open, close) + 1, maxNesting, params });
  }
  return out;
}

function lexicalHalstead(views: SourceViews): number {
  const operators = new Map<string, number>();
  const operands = new Map<string, number>();
  for (const m of views.codeOnly.matchAll(/[A-Za-z_$][\w$]*|\d[\d.]*|==|!=|<=|>=|&&|\|\||=>|->|::|[^\s\w]/g)) {
    const tok = m[0];
    const bucket = /^[A-Za-z_$\d]/.test(tok) ? operands : operators;
    bucket.set(tok, (bucket.get(tok) ?? 0) + 1);
  }
  return volume(operators, operands);
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function maintainabilityIndex(halsteadVolume: number, complexity: number, sloc: number): number {
  if (sloc === 0) return 100;
  const raw = 171 - 5.2 * Math.log(Math.max(halsteadVolume, 1)) - 0.23 * complexity - 16.2 * Math.log(sloc);
  return Math.round(Math.max(0, Math.min(100, (raw * 100) / 171)));
}

export function computeMetrics(views: SourceViews, lang: Language, sf: ts.SourceFile | null, index: LineIndex): FileMetrics {
  const lines = views.raw.split("\n");
  const loc = lines.length;
  const sloc = views.noComments.split("\n").filter((l) => l.trim().length > 0).length;

  let functions: FunctionMetric[];
  let complexity: number;
  let halsteadVolume: number;

  if (sf) {
    ({ functions, complexity } = astMetrics(sf));
    halsteadVolume = astHalstead(sf);
  } else {
    functions = lang === "json" || lang === "unknown" ? [] : lexicalFunctions(views, lang, index);
    const decisions = DECISION_RE[lang] ?? DEFAULT_DECISIONS;
    complexity = lang === "json" ? 1 : (views.codeOnly.match(new RegExp(decisions.source, "g")) ?? []).length + 1;
    halsteadVolume = lexicalHalstead(views);
  }

  return {
    loc,
    sloc,
    commentLines: views.commentLines,
    functions,
    complexity,
    maintainability: maintainabilityIndex(halsteadVolume, complexity, sloc),
    halsteadVolume: Math.round(halsteadVolume),
  };
}
