import ts from "typescript";
import type { Finding, TraceStep } from "../types";
import { makeFinding } from "../finding";
import {
  ARG_PASSTHROUGH,
  ARRAY_CALLBACK_METHODS,
  ASSIGNMENT_SINKS,
  HTTP_HANDLER_NAMES,
  PASSTHROUGH_METHODS,
  REQUEST_BINDINGS,
  RESPONSE_WRITERS,
  ROUTER_CALL,
  SAFE_TAGS,
  SANITIZER_CALLS,
  SINKS,
  SOURCE_CALLS,
  SOURCE_MEMBERS,
  type SinkSpec,
} from "./model";

/**
 * Intra-file taint analysis for JavaScript / TypeScript on the TypeScript
 * compiler AST.
 *
 *  - Flow-sensitive within straight-line code, scope-aware (block, function, closure).
 *  - Interprocedural through *function summaries*: every local function is first
 *    analysed with symbolic taint on its parameters, recording which parameters
 *    reach a sink and which flow to the return value. Call sites then apply the
 *    summary, so `handler → buildQuery(id) → db.query(sql)` is reported with the
 *    full cross-function trace.
 */

type Origin = { kind: "source" } | { kind: "param"; index: number };

interface Taint {
  origin: Origin;
  steps: TraceStep[];
  confidence: number;
  /**
   * True while the value may still be a structured object (parsed JSON body, qs query)
   * rather than a primitive string. Cleared by string conversion. Drives NoSQL checks.
   */
  structured: boolean;
}

interface SinkHit {
  sink: SinkSpec;
  paramIndex: number;
  steps: TraceStep[];
  confidence: number;
  severityOverride?: SinkSpec["severity"];
  note?: string;
  /** The sink node inside the summarised function, reported at the caller's call site. */
  sinkNode?: ts.Node;
}

interface FunctionSummary {
  name: string;
  /** Parameter indexes whose taint flows into the return value. */
  returns: Set<number>;
  /** Parameter-to-sink flows discovered inside the function. */
  sinks: SinkHit[];
}

const MAX_STEPS = 8;

class Scope {
  private vars = new Map<string, Taint | null>();
  constructor(readonly parent?: Scope) {}
  declare(name: string, taint: Taint | null) {
    this.vars.set(name, taint);
  }
  has(name: string): boolean {
    return this.vars.has(name) || !!this.parent?.has(name);
  }
  assign(name: string, taint: Taint | null) {
    if (this.vars.has(name) || !this.parent?.has(name)) this.vars.set(name, taint);
    else this.parent.assign(name, taint);
  }
  lookup(name: string): Taint | null {
    if (this.vars.has(name)) return this.vars.get(name) ?? null;
    return this.parent?.lookup(name) ?? null;
  }
}

function scriptKindFor(file: string): ts.ScriptKind {
  if (/\.tsx$/i.test(file)) return ts.ScriptKind.TSX;
  if (/\.(?:m|c)?ts$/i.test(file)) return ts.ScriptKind.TS;
  if (/\.jsx$/i.test(file)) return ts.ScriptKind.JSX;
  // Plain .js files frequently contain JSX in React projects; JSX kind parses both.
  return ts.ScriptKind.JSX;
}

export function parseSource(file: string, code: string): ts.SourceFile {
  return ts.createSourceFile(file || "input.ts", code, ts.ScriptTarget.Latest, true, scriptKindFor(file));
}

type FunctionLike = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;

export class TaintAnalyzer {
  private summaries = new Map<string, FunctionSummary>();
  private findings: Finding[] = [];
  private mode: "summary" | "report" = "report";
  private currentSummary: FunctionSummary | null = null;
  private reported = new Set<string>();

  constructor(private sf: ts.SourceFile, private file: string) {}

  run(): Finding[] {
    const functions = this.collectFunctions();
    // Two rounds let summaries of callees feed the summaries of their callers.
    for (let round = 0; round < 2; round++) {
      this.mode = "summary";
      for (const [name, fn] of functions) this.summarise(name, fn);
    }
    this.mode = "report";
    const root = new Scope();
    for (const stmt of this.sf.statements) this.visit(stmt, root);
    return this.findings;
  }

  // ─── helpers ──────────────────────────────────────────────────────────────

  private line(node: ts.Node): number {
    return this.sf.getLineAndCharacterOfPosition(node.getStart(this.sf)).line + 1;
  }

  private text(node: ts.Node): string {
    return node.getText(this.sf);
  }

  private snippet(node: ts.Node): string {
    const t = this.text(node).replace(/\s+/g, " ");
    return t.length > 90 ? t.slice(0, 87) + "…" : t;
  }

  private calleeText(expr: ts.Expression): string {
    return this.text(expr).replace(/\?\./g, ".").replace(/\s+/g, "").replace(/^this\./, "this.");
  }

  private step(kind: TraceStep["kind"], node: ts.Node, label: string): TraceStep {
    return { kind, line: this.line(node), label, snippet: this.snippet(node) };
  }

  private extend(t: Taint, step: TraceStep, factor = 1): Taint {
    const last = t.steps[t.steps.length - 1];
    if (last && last.line === step.line && last.label === step.label) return { ...t, confidence: t.confidence * factor };
    const steps = [...t.steps, step];
    // Keep the source and the most recent hops — the middle of very long chains adds noise.
    const trimmed = steps.length > MAX_STEPS ? [steps[0], ...steps.slice(-(MAX_STEPS - 1))] : steps;
    return { ...t, steps: trimmed, confidence: t.confidence * factor };
  }

  private union(a: Taint | null, b: Taint | null): Taint | null {
    if (!a) return b;
    if (!b) return a;
    // Prefer real sources over symbolic parameters, then the more confident flow.
    if (a.origin.kind !== b.origin.kind) return a.origin.kind === "source" ? a : b;
    return a.confidence >= b.confidence ? a : b;
  }

  private collectFunctions(): Map<string, FunctionLike> {
    const out = new Map<string, FunctionLike>();
    const visit = (node: ts.Node) => {
      if (ts.isFunctionDeclaration(node) && node.name && node.body) out.set(node.name.text, node);
      else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
        out.set(node.name.text, node.initializer);
      } else if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.body) out.set(`this.${node.name.text}`, node);
      ts.forEachChild(node, visit);
    };
    visit(this.sf);
    return out;
  }

  private summarise(name: string, fn: FunctionLike) {
    const summary: FunctionSummary = { name, returns: new Set(), sinks: [] };
    const scope = new Scope();
    fn.parameters.forEach((p, index) => {
      const taint: Taint = {
        origin: { kind: "param", index },
        steps: [this.step("propagation", p, `enters ${name}() as parameter ${index + 1}`)],
        confidence: 1,
        structured: true,
      };
      this.bindPattern(p.name, taint, scope);
    });
    const prev = this.currentSummary;
    this.currentSummary = summary;
    this.visitFunctionBody(fn, scope);
    this.currentSummary = prev;
    this.summaries.set(name, summary);
  }

  // ─── sources & sinks ──────────────────────────────────────────────────────

  private sourceFromMember(node: ts.Expression): Taint | null {
    const text = this.calleeText(node);
    for (const src of SOURCE_MEMBERS) {
      if (src.pattern.test(text)) {
        const whole = /\.(?:body|query|params)\b/.test(text);
        return { origin: { kind: "source" }, steps: [this.step("source", node, src.label)], confidence: 0.95, structured: whole };
      }
    }
    return null;
  }

  private sourceFromCall(callee: string, node: ts.CallExpression): Taint | null {
    for (const src of SOURCE_CALLS) {
      if (src.pattern.test(callee)) {
        const whole = /\.(?:json|formData)$/.test(callee);
        return { origin: { kind: "source" }, steps: [this.step("source", node, src.label)], confidence: 0.95, structured: whole };
      }
    }
    return null;
  }

  private isSanitizer(callee: string): boolean {
    return SANITIZER_CALLS.some((re) => re.test(callee));
  }

  private emit(hit: SinkHit, sinkNode: ts.Node) {
    if (this.mode === "summary") {
      this.currentSummary?.sinks.push({ ...hit, sinkNode });
      return;
    }
    const steps = [...hit.steps, this.step("sink", sinkNode, hit.note ?? `reaches ${hit.sink.title.toLowerCase()} sink`)];
    const start = this.sf.getLineAndCharacterOfPosition(sinkNode.getStart(this.sf));
    const end = this.sf.getLineAndCharacterOfPosition(sinkNode.getEnd());
    const key = `${hit.sink.id}:${start.line}:${start.character}`;
    if (this.reported.has(key)) return;
    this.reported.add(key);

    const source = steps[0];
    this.findings.push(
      makeFinding({
        rule: { ...hit.sink, title: hit.sink.title },
        file: this.file,
        location: { line: start.line + 1, column: start.character + 1, endLine: end.line + 1, endColumn: end.character + 1 },
        snippet: this.sf.text.split("\n")[start.line] ?? this.snippet(sinkNode),
        confidence: hit.sink.confidence * hit.confidence,
        detector: "taint",
        trace: steps,
        severity: hit.severityOverride,
        title: `${hit.sink.title}: ${source.label} → line ${start.line + 1}`,
        description: hit.note ? `${hit.sink.description} ${hit.note}.` : hit.sink.description,
      })
    );
  }

  private checkSink(sink: SinkSpec, taint: Taint | null, argNode: ts.Expression, sinkNode: ts.Node) {
    if (!taint) return;
    if (sink.id === "AEG-TAINT-NOSQL" && !taint.structured) return;
    let severityOverride: SinkSpec["severity"] | undefined;
    let note: string | undefined;
    let factor = 1;

    // An outbound URL whose scheme + host are fixed only lets the attacker steer the path.
    if (sink.id === "AEG-TAINT-SSRF" && this.hasFixedOrigin(argNode)) {
      severityOverride = "low";
      factor = 0.6;
      note = "the host is fixed, so only the path/query is attacker-controlled";
    }
    const hit: SinkHit = {
      sink,
      paramIndex: taint.origin.kind === "param" ? taint.origin.index : -1,
      steps: taint.steps,
      confidence: taint.confidence * factor,
      severityOverride,
      note,
    };
    if (taint.origin.kind === "param" && this.mode === "report") return; // only meaningful inside summaries
    this.emit(hit, sinkNode);
  }

  private hasFixedOrigin(node: ts.Expression): boolean {
    const head = ts.isTemplateExpression(node)
      ? node.head.text
      : ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken && ts.isStringLiteralLike(node.left)
        ? node.left.text
        : null;
    return head !== null && /^https?:\/\/[^/]+\//i.test(head);
  }

  // ─── statements ───────────────────────────────────────────────────────────

  private visit(node: ts.Node, scope: Scope): void {
    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) this.visitDeclaration(decl, scope);
      return;
    }
    if (ts.isFunctionDeclaration(node)) {
      if (node.name) scope.declare(node.name.text, null);
      if (this.mode === "report") this.visitFunction(node, scope);
      return;
    }
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      for (const member of node.members) {
        if ((ts.isMethodDeclaration(member) || ts.isConstructorDeclaration(member) || ts.isGetAccessor(member) || ts.isSetAccessor(member)) && member.body) {
          if (this.mode === "report") this.visitFunction(member as FunctionLike, scope);
        } else if (ts.isPropertyDeclaration(member) && member.initializer) {
          this.evalExpr(member.initializer, scope);
        }
      }
      return;
    }
    if (ts.isBlock(node)) {
      const inner = new Scope(scope);
      for (const s of node.statements) this.visit(s, inner);
      return;
    }
    if (ts.isReturnStatement(node)) {
      if (node.expression) {
        const t = this.evalExpr(node.expression, scope);
        if (t && t.origin.kind === "param" && this.currentSummary) this.currentSummary.returns.add(t.origin.index);
      }
      return;
    }
    if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      const iter = this.evalExpr(node.expression, scope);
      const inner = new Scope(scope);
      const init = node.initializer;
      const element = iter ? this.extend(iter, this.step("propagation", init, "loop variable")) : null;
      if (ts.isVariableDeclarationList(init)) {
        for (const d of init.declarations) this.bindPattern(d.name, element, inner);
      } else {
        this.assignTo(init, element, inner);
      }
      this.visit(node.statement, inner);
      return;
    }
    if (ts.isExpressionStatement(node)) {
      this.evalExpr(node.expression, scope);
      return;
    }
    if (ts.isExpression(node)) {
      this.evalExpr(node, scope);
      return;
    }
    ts.forEachChild(node, (child) => this.visit(child, scope));
  }

  private visitDeclaration(decl: ts.VariableDeclaration, scope: Scope) {
    if (!decl.initializer) {
      this.bindPattern(decl.name, null, scope);
      return;
    }
    const value = this.evalExpr(decl.initializer, scope);
    const label = ts.isIdentifier(decl.name) ? `assigned to \`${decl.name.text}\`` : "destructured";
    this.bindPattern(decl.name, value ? this.extend(value, this.step("propagation", decl, label)) : null, scope);
  }

  private bindPattern(name: ts.BindingName, taint: Taint | null, scope: Scope) {
    if (ts.isIdentifier(name)) {
      scope.declare(name.text, taint);
      return;
    }
    for (const el of name.elements) {
      if (ts.isOmittedExpression(el)) continue;
      this.bindPattern(el.name, taint, scope);
    }
  }

  private visitFunction(fn: FunctionLike | ts.ConstructorDeclaration | ts.AccessorDeclaration, outer: Scope, seed?: Taint | null) {
    const scope = new Scope(outer);
    const name = (fn as ts.FunctionDeclaration).name;
    const isHandler = (name && ts.isIdentifier(name) && HTTP_HANDLER_NAMES.test(name.text)) || this.isRouterCallback(fn);

    fn.parameters.forEach((p, i) => {
      if (i === 0 && seed) {
        this.bindPattern(p.name, this.extend(seed, this.step("propagation", p, "callback parameter")), scope);
        return;
      }
      if (isHandler && ts.isObjectBindingPattern(p.name)) {
        for (const el of p.name.elements) {
          const key = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : "";
          if (REQUEST_BINDINGS.has(key)) {
            const t: Taint = { origin: { kind: "source" }, steps: [this.step("source", el, "HTTP request input")], confidence: 0.9, structured: true };
            this.bindPattern(el.name, t, scope);
          } else {
            this.bindPattern(el.name, null, scope);
          }
        }
        return;
      }
      this.bindPattern(p.name, null, scope);
    });
    this.visitFunctionBody(fn, scope);
  }

  private isRouterCallback(fn: ts.Node): boolean {
    const parent = fn.parent;
    return !!parent && ts.isCallExpression(parent) && ROUTER_CALL.test(this.calleeText(parent.expression));
  }

  private visitFunctionBody(fn: FunctionLike | ts.ConstructorDeclaration | ts.AccessorDeclaration, scope: Scope) {
    const body = fn.body;
    if (!body) return;
    if (ts.isBlock(body)) {
      for (const s of body.statements) this.visit(s, scope);
    } else {
      const t = this.evalExpr(body, scope);
      if (t && t.origin.kind === "param" && this.currentSummary) this.currentSummary.returns.add(t.origin.index);
    }
  }

  private assignTo(target: ts.Node, value: Taint | null, scope: Scope) {
    if (ts.isIdentifier(target)) {
      scope.assign(target.text, value ? this.extend(value, this.step("propagation", target.parent ?? target, `assigned to \`${target.text}\``)) : null);
      return;
    }
    if (ts.isObjectLiteralExpression(target) || ts.isArrayLiteralExpression(target)) {
      const elements = ts.isObjectLiteralExpression(target) ? target.properties : target.elements;
      for (const el of elements) {
        if (ts.isShorthandPropertyAssignment(el)) scope.assign(el.name.text, value);
        else if (ts.isPropertyAssignment(el)) this.assignTo(el.initializer, value, scope);
        else if (ts.isIdentifier(el)) scope.assign(el.text, value);
      }
      return;
    }
    if (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
      const targetText = this.calleeText(target);
      if (value) {
        for (const { target: re, sink } of ASSIGNMENT_SINKS) {
          if (re.test(targetText)) this.checkSink(sink, value, target, target.parent ?? target);
        }
      }
      // obj[userKey] = value  → prototype pollution when the key is attacker-controlled.
      if (ts.isElementAccessExpression(target)) {
        const keyTaint = this.evalExpr(target.argumentExpression, scope);
        if (keyTaint && !ts.isNumericLiteral(target.argumentExpression)) {
          const nested = ts.isElementAccessExpression(target.expression);
          const sink = SINKS.find((s) => s.id === "AEG-TAINT-PROTO")!;
          this.checkSink(
            { ...sink, title: "Prototype pollution via computed property", severity: nested ? "high" : "medium", confidence: nested ? 0.75 : 0.5 },
            this.extend(keyTaint, this.step("propagation", target.argumentExpression, "used as property key")),
            target.argumentExpression,
            target.parent ?? target
          );
        }
      }
      // Writing a tainted value into an object taints the object itself.
      if (value) {
        let base: ts.Expression = target.expression;
        while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) base = base.expression;
        if (ts.isIdentifier(base)) scope.assign(base.text, this.union(scope.lookup(base.text), value));
      }
    }
  }

  // ─── expressions ──────────────────────────────────────────────────────────

  private evalExpr(node: ts.Expression, scope: Scope): Taint | null {
    if (ts.isIdentifier(node)) return scope.lookup(node.text);

    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node) || ts.isAwaitExpression(node)) {
      return this.evalExpr(node.expression, scope);
    }
    if (ts.isSpreadElement(node)) return this.evalExpr(node.expression, scope);

    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const src = this.sourceFromMember(node);
      if (src) return src;
      if (ts.isElementAccessExpression(node)) this.evalExpr(node.argumentExpression, scope);
      const obj = this.evalExpr(node.expression, scope);
      if (!obj) return null;
      if (ts.isPropertyAccessExpression(node) && node.name.text === "length") return null;
      return obj;
    }

    if (ts.isCallExpression(node)) return this.evalCall(node, scope);
    if (ts.isNewExpression(node)) return this.evalNew(node, scope);

    if (ts.isTaggedTemplateExpression(node)) {
      const tag = this.calleeText(node.tag);
      let t: Taint | null = null;
      if (ts.isTemplateExpression(node.template)) for (const span of node.template.templateSpans) t = this.union(t, this.evalExpr(span.expression, scope));
      return SAFE_TAGS.test(tag) ? null : t;
    }

    if (ts.isTemplateExpression(node)) {
      let t: Taint | null = null;
      for (const span of node.templateSpans) t = this.union(t, this.evalExpr(span.expression, scope));
      return t ? this.extend({ ...t, structured: false }, this.step("propagation", node, "interpolated into string")) : null;
    }

    if (ts.isBinaryExpression(node)) return this.evalBinary(node, scope);

    if (ts.isConditionalExpression(node)) {
      this.evalExpr(node.condition, scope);
      return this.union(this.evalExpr(node.whenTrue, scope), this.evalExpr(node.whenFalse, scope));
    }

    if (ts.isObjectLiteralExpression(node)) {
      let t: Taint | null = null;
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p)) t = this.union(t, this.evalExpr(p.initializer, scope));
        else if (ts.isShorthandPropertyAssignment(p)) t = this.union(t, scope.lookup(p.name.text));
        else if (ts.isSpreadAssignment(p)) t = this.union(t, this.evalExpr(p.expression, scope));
        else if (ts.isMethodDeclaration(p) && this.mode === "report") this.visitFunction(p, scope);
      }
      return t;
    }

    if (ts.isArrayLiteralExpression(node)) {
      let t: Taint | null = null;
      for (const el of node.elements) t = this.union(t, this.evalExpr(el, scope));
      return t;
    }

    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      this.visitFunction(node, scope);
      return null;
    }

    if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node) || ts.isTypeOfExpression(node) || ts.isVoidExpression(node) || ts.isDeleteExpression(node)) {
      ts.forEachChild(node, (c) => void (ts.isExpression(c) && this.evalExpr(c, scope)));
      return null; // numeric / boolean / undefined results
    }

    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) || ts.isJsxFragment(node)) {
      this.visitJsx(node, scope);
      return null;
    }

    ts.forEachChild(node, (c) => {
      if (ts.isExpression(c)) this.evalExpr(c, scope);
      else this.visit(c, scope);
    });
    return null;
  }

  private evalBinary(node: ts.BinaryExpression, scope: Scope): Taint | null {
    const op = node.operatorToken.kind;
    if (op === ts.SyntaxKind.EqualsToken) {
      const value = this.evalExpr(node.right, scope);
      this.assignTo(node.left, value, scope);
      return value;
    }
    if (op === ts.SyntaxKind.PlusEqualsToken || op === ts.SyntaxKind.BarBarEqualsToken || op === ts.SyntaxKind.QuestionQuestionEqualsToken) {
      const value = this.union(this.evalExpr(node.left, scope), this.evalExpr(node.right, scope));
      this.assignTo(node.left, value, scope);
      return value;
    }
    const left = this.evalExpr(node.left, scope);
    const right = this.evalExpr(node.right, scope);
    switch (op) {
      case ts.SyntaxKind.PlusToken: {
        const t = this.union(left, right);
        return t ? this.extend({ ...t, structured: false }, this.step("propagation", node, "concatenated into string")) : null;
      }
      case ts.SyntaxKind.BarBarToken:
      case ts.SyntaxKind.QuestionQuestionToken:
      case ts.SyntaxKind.AmpersandAmpersandToken:
      case ts.SyntaxKind.CommaToken:
        return op === ts.SyntaxKind.CommaToken ? right : this.union(left, right);
      default:
        // Comparisons, arithmetic, instanceof, in — all produce booleans or numbers.
        return null;
    }
  }

  private evalNew(node: ts.NewExpression, scope: Scope): Taint | null {
    const callee = this.calleeText(node.expression);
    const args = node.arguments ?? [];
    const argTaints = args.map((a) => this.evalExpr(a, scope));
    for (const sink of SINKS) {
      if (!sink.isNew || !sink.callee.test(callee)) continue;
      const idx = sink.args === "any" ? args.map((_, i) => i) : sink.args;
      for (const i of idx) if (args[i]) this.checkSink(sink, argTaints[i], args[i], node);
    }
    if (/^(?:URL|URLSearchParams|Request|Headers|FormData|Map|Set|Buffer|String)$/.test(callee)) {
      const t = argTaints.reduce<Taint | null>((acc, x) => this.union(acc, x), null);
      return t ? this.extend(t, this.step("propagation", node, `wrapped in ${callee}`)) : null;
    }
    if (/^Response$/.test(callee) && args[0]) this.checkReflected(args[0], argTaints[0], node);
    return null;
  }

  private evalCall(node: ts.CallExpression, scope: Scope): Taint | null {
    const callee = this.calleeText(node.expression);
    const args = node.arguments;

    // Receiver taint for method calls (`input.trim()`, `searchParams.get()`).
    let receiver: Taint | null = null;
    let method = "";
    if (ts.isPropertyAccessExpression(node.expression)) {
      method = node.expression.name.text;
      receiver = this.evalExpr(node.expression.expression, scope);
    } else if (ts.isElementAccessExpression(node.expression)) {
      receiver = this.evalExpr(node.expression.expression, scope);
    }

    // Callbacks on tainted collections receive tainted elements.
    const argTaints = args.map((a, i) => {
      if ((ts.isArrowFunction(a) || ts.isFunctionExpression(a)) && i === 0 && receiver && ARRAY_CALLBACK_METHODS.has(method)) {
        this.visitFunction(a, scope, receiver);
        return null;
      }
      return this.evalExpr(a, scope);
    });

    // Sinks
    for (const sink of SINKS) {
      if (sink.isNew || !sink.callee.test(callee)) continue;
      if (sink.id === "AEG-TAINT-CODE" && /setTimeout|setInterval/.test(callee) && args[0] && (ts.isArrowFunction(args[0]) || ts.isFunctionExpression(args[0]))) continue;
      const idx = sink.args === "any" ? args.map((_, i) => i) : sink.args;
      for (const i of idx) if (args[i]) this.checkSink(sink, argTaints[i], args[i], node);
    }
    if (RESPONSE_WRITERS.test(callee) && args[0]) this.checkReflected(args[0], argTaints[0], node);

    // Local function summaries (interprocedural flows).
    const summary = this.summaries.get(callee) ?? (ts.isIdentifier(node.expression) ? this.summaries.get(node.expression.text) : undefined);
    if (summary && summary !== this.currentSummary) {
      for (const hit of summary.sinks) {
        const actual = argTaints[hit.paramIndex];
        if (!actual) continue;
        const joined: Taint = {
          ...actual,
          steps: [...actual.steps, this.step("propagation", node, `passed to ${summary.name}()`), ...hit.steps.slice(1)],
          confidence: actual.confidence * hit.confidence * 0.95,
        };
        const argNode = args[hit.paramIndex];
        if (actual.origin.kind === "param") {
          if (this.mode === "summary") this.currentSummary?.sinks.push({ ...hit, paramIndex: actual.origin.index, steps: joined.steps, confidence: joined.confidence });
        } else {
          this.checkSink(hit.sink, joined, argNode, hit.sinkNode ?? node);
        }
      }
      let ret: Taint | null = null;
      for (const i of summary.returns) ret = this.union(ret, argTaints[i] ?? null);
      return ret ? this.extend(ret, this.step("propagation", node, `returned from ${summary.name}()`)) : null;
    }

    const source = this.sourceFromCall(callee, node);
    if (source) return source;
    if (this.isSanitizer(callee)) return null;

    if (receiver) {
      const factor = PASSTHROUGH_METHODS.has(method) ? 1 : 0.85;
      return this.extend({ ...receiver, structured: method === "json" || method === "formData" ? receiver.structured : false }, this.step("propagation", node, `through .${method || "call"}()`), factor);
    }

    const argTaint = argTaints.reduce<Taint | null>((acc, t) => this.union(acc, t), null);
    if (!argTaint) return null;
    if (ARG_PASSTHROUGH.test(callee)) return this.extend({ ...argTaint, structured: false }, this.step("propagation", node, `through ${callee}()`));
    // Unknown function: assume the value flows through, with reduced confidence.
    return this.extend({ ...argTaint, structured: false }, this.step("propagation", node, `through ${callee}()`), 0.75);
  }

  /** Reflected XSS: tainted data concatenated into an HTML string sent as a response. */
  private checkReflected(arg: ts.Expression, taint: Taint | null, node: ts.Node) {
    if (!taint) return;
    const text = this.text(arg);
    if (!/<\/?[a-z][\w-]*[\s>]/i.test(text)) return;
    const sink = SINKS.find((s) => s.id === "AEG-TAINT-XSS")!;
    this.checkSink({ ...sink, title: "Reflected cross-site scripting" }, taint, arg, node);
  }

  private visitJsx(node: ts.Node, scope: Scope) {
    const walk = (n: ts.Node) => {
      if (ts.isJsxAttribute(n) && n.name.getText(this.sf) === "dangerouslySetInnerHTML" && n.initializer && ts.isJsxExpression(n.initializer) && n.initializer.expression) {
        const t = this.evalExpr(n.initializer.expression, scope);
        if (t) {
          const sink = SINKS.find((s) => s.id === "AEG-TAINT-XSS")!;
          this.checkSink({ ...sink, title: "Cross-site scripting via dangerouslySetInnerHTML" }, t, n.initializer.expression, n);
        }
        return;
      }
      if (ts.isJsxExpression(n) && n.expression) {
        this.evalExpr(n.expression, scope);
        return;
      }
      ts.forEachChild(n, walk);
    };
    walk(node);
  }

}

export function analyzeTaint(sf: ts.SourceFile, file: string): Finding[] {
  return new TaintAnalyzer(sf, file).run();
}
