import ts from "typescript";
import type { Finding, SourceLocation, TraceStep } from "../types";
import { makeFinding } from "../finding";
import {
  ARG_PASSTHROUGH,
  ARRAY_CALLBACK_METHODS,
  ASSIGNMENT_SINKS,
  DECODERS,
  HTTP_HANDLER_NAMES,
  PARAM_DECORATORS,
  PASSTHROUGH_METHODS,
  REQUEST_BINDINGS,
  REQUEST_DECORATORS,
  REQUEST_TYPES,
  RESPONSE_WRITERS,
  ROUTER_CALL,
  SAFE_TAGS,
  SINKS,
  SOURCE_CALLS,
  SOURCE_MEMBERS,
  VALIDATING_PIPES,
  VERB_HANDLER_NAMES,
  sanitizerScope,
  type SinkSpec,
} from "./model";

/**
 * Intra-file taint analysis for JavaScript / TypeScript on the TypeScript
 * compiler AST.
 *
 *  - Flow-sensitive and scope-aware (block, function, closure). Branches of `if`,
 *    `switch`, `try` and loops are analysed separately and joined afterwards, so a
 *    value that is tainted on any path into a sink is reported, and one that is
 *    validated or replaced on every path is not.
 *  - Sanitisers are context-aware: an HTML escaper clears a value for HTML sinks
 *    only, and object literals are tracked per field.
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
  /** The value has been concatenated into an HTML fragment (drives reflected-XSS checks across helpers). */
  markup?: boolean;
  /** Sink ids this value has been escaped for (`escapeHtml(x)` is safe in HTML, still dangerous in SQL). */
  neutralised?: ReadonlySet<string>;
  /** Per-property taint, when the value is an object literal whose keys are all known. */
  fields?: ReadonlyMap<string, Taint | null>;
}

/** Where a sink call lives. Plain data, so summaries can cross file boundaries. */
export interface SinkSite {
  file: string;
  location: SourceLocation;
  snippet: string;
}

export interface SinkHit {
  sink: SinkSpec;
  paramIndex: number;
  steps: TraceStep[];
  confidence: number;
  severityOverride?: SinkSpec["severity"];
  note?: string;
  /** The sink inside the summarised function; findings are reported there. */
  site?: SinkSite;
}

interface FunctionSummary {
  name: string;
  /** Parameter indexes whose taint flows into the return value. */
  returns: Set<number>;
  /** Parameters returned embedded in HTML markup. */
  returnsMarkup: Set<number>;
  /** Parameter-to-sink flows discovered inside the function. */
  sinks: SinkHit[];
}

/** A function summary exported from one module for use by its importers. */
export interface ExportedSummary {
  name: string;
  file: string;
  returns: number[];
  returnsMarkup: number[];
  sinks: SinkHit[];
}

/** What a local name refers to in another module of the same project. */
export type ImportBinding = { kind: "fn"; summary: ExportedSummary } | { kind: "ns"; members: Map<string, ExportedSummary> };
export type ImportMap = Map<string, ImportBinding>;

/** Names validated by a condition, and on which branch (true / false) they are known to be safe. */
interface Guard {
  /** Local variables proven safe. */
  names: string[];
  /** Non-local expressions proven safe, as normalised source text (e.g. `req.query.next`). */
  texts: string[];
  whenTrue: boolean;
}

const MAX_STEPS = 8;
const HTML_TAG = /<\/?[a-z][\w-]*[\s>]/i;

/** How a statement leaves the code that follows it: not at all, out of a loop / switch, or out of the function. */
type ExitKind = "none" | "break" | "continue" | "leave";

interface Branch {
  fork: Scope;
  exit: ExitKind;
}

class Scope {
  private vars = new Map<string, Taint | null>();
  private clean = new Set<string>();
  private aliases = new Set<string>();
  /**
   * Present on scopes that open a conditional branch. Writes to variables that
   * live outside the branch are buffered here instead of being applied, then
   * merged with the other branches once they have all been analysed.
   */
  private overlay: Map<string, Taint | null> | null;
  /** Overlay entries that come from an assignment rather than from a guard. */
  private written = new Set<string>();

  constructor(
    readonly parent?: Scope,
    branch = false,
    /** Function (or module) scopes are where `var` declarations live. */
    readonly isFunction = false
  ) {
    this.overlay = branch ? new Map() : null;
  }

  /** Marks an expression (by normalised text) as validated within this scope. */
  markClean(text: string) {
    this.clean.add(text);
  }
  /** `e.data` being validated also covers `e.data.html` and `e.data[0]`. */
  isClean(text: string): boolean {
    for (const c of this.clean) if (text === c || text.startsWith(`${c}.`) || text.startsWith(`${c}[`)) return true;
    return !!this.parent?.isClean(text);
  }
  cleanTexts(): string[] {
    return [...this.clean];
  }
  declare(name: string, taint: Taint | null) {
    this.vars.set(name, taint);
  }
  /** `var` is function-scoped: make sure the name exists there, then assign through the normal path. */
  hoist(name: string) {
    if (!this.isFunction && this.parent) this.parent.hoist(name);
    else if (!this.vars.has(name)) this.vars.set(name, null);
  }
  /** A guard proved `name` safe on this branch. */
  refine(name: string) {
    if (this.overlay && !this.vars.has(name)) {
      this.overlay.set(name, null);
      this.written.delete(name);
    } else this.vars.set(name, null);
  }
  /** The parameter `name` is the incoming request (so `name.query` is a source even if it isn't called `req`). */
  alias(name: string) {
    this.aliases.add(name);
  }
  isAlias(name: string): boolean {
    if (this.aliases.has(name)) return true;
    if (this.vars.has(name)) return false;
    return !!this.parent?.isAlias(name);
  }
  has(name: string): boolean {
    return this.vars.has(name) || !!this.overlay?.has(name) || !!this.parent?.has(name);
  }
  assign(name: string, taint: Taint | null) {
    if (this.vars.has(name)) this.vars.set(name, taint);
    else if (this.overlay && (this.overlay.has(name) || this.parent?.has(name))) {
      this.overlay.set(name, taint);
      this.written.add(name);
    } else if (this.parent?.has(name)) this.parent.assign(name, taint);
    else this.vars.set(name, taint);
  }
  lookup(name: string): Taint | null {
    if (this.vars.has(name)) return this.vars.get(name) ?? null;
    if (this.overlay?.has(name)) return this.overlay.get(name) ?? null;
    return this.parent?.lookup(name) ?? null;
  }
  /** Outer variables this branch assigned or refined. */
  touched(): string[] {
    return this.overlay ? [...this.overlay.keys()] : [];
  }
  touches(name: string): boolean {
    return !!this.overlay?.has(name);
  }
  wrote(name: string): boolean {
    return this.written.has(name);
  }
  branchValue(name: string): Taint | null {
    return this.overlay?.get(name) ?? null;
  }
  /**
   * Starts this branch from where `from` ended, for paths that may or may not
   * have run it first (a `case` reached by fall-through, a `catch` after a
   * partly executed `try`).
   */
  inherit(from: Scope, merge: (a: Taint | null, b: Taint | null) => Taint | null) {
    if (!this.overlay) return;
    for (const name of from.touched()) {
      if (!from.wrote(name)) continue;
      this.overlay.set(name, merge(this.parent?.lookup(name) ?? null, from.branchValue(name)));
      this.written.add(name);
    }
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
  /** Taint stored on `this.<field>` while visiting the current class (field-sensitive, flow-insensitive). */
  private thisFields = new Map<string, Taint>();
  /** One entry per function being visited: the taint of everything it returns. */
  private frames: Array<{ returned: Taint | null }> = [];
  /** Depth of `frames` at which returns belong to the function being summarised. */
  private summaryFrame = -1;
  private loopDepth = 0;
  private summaryKeys = new Set<string>();
  /** The module starts with a "use server" directive, so its exports are callable by any client. */
  private useServerFile: boolean;
  /** What the file's declarations say about names: classes, instance types, renamed callees, Zod schemas. */
  private facts: FileFacts;

  constructor(
    private sf: ts.SourceFile,
    private file: string,
    private imports: ImportMap = new Map()
  ) {
    this.useServerFile = hasDirective(sf.statements, "use server");
    this.facts = collectFacts(sf);
  }

  run(): Finding[] {
    this.buildSummaries();
    this.mode = "report";
    const root = new Scope(undefined, false, true);
    for (const stmt of this.sf.statements) this.visit(stmt, root);
    return this.findings;
  }

  private summariesBuilt = false;

  private buildSummaries() {
    if (this.summariesBuilt) return;
    this.summariesBuilt = true;
    const functions = this.collectFunctions();
    // Two rounds let summaries of callees feed the summaries of their callers.
    for (let round = 0; round < 2; round++) {
      this.mode = "summary";
      for (const [name, fn] of functions) this.summarise(name, fn);
    }
  }

  /**
   * Summaries of this module's exported functions, keyed by export name
   * (`default` for default exports and `module.exports = fn`).
   */
  exportSummaries(): Map<string, ExportedSummary> {
    this.buildSummaries();
    const out = new Map<string, ExportedSummary>();
    const publish = (key: string, name: string, summary: FunctionSummary) =>
      out.set(key, {
        name,
        file: this.file,
        returns: [...summary.returns],
        returnsMarkup: [...summary.returnsMarkup],
        sinks: summary.sinks.map((h) => ({ ...h, steps: h.steps.map((st) => (st.file ? st : { ...st, file: this.file })) })),
      });
    for (const [exported, local] of exportedFunctionNames(this.sf)) {
      const summary = this.summaries.get(local);
      if (summary) publish(exported, exported === "default" ? local : exported, summary);
      // An exported class publishes its methods as `Class.method`, for `new Class().method(x)` in importers.
      if (!this.facts.classes.has(local)) continue;
      for (const [key, method] of this.summaries) {
        if (key.startsWith(`${local}#`)) publish(`${exported}.${key.slice(local.length + 1)}`, `${local}.${key.slice(local.length + 1)}`, method);
      }
    }
    return out;
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
    const pick = a.origin.kind !== b.origin.kind ? (a.origin.kind === "source" ? a : b) : a.confidence >= b.confidence ? a : b;
    const other = pick === a ? b : a;
    // The combined value is only safe where both halves are, and only field-precise if they are the same object.
    const neutralised = intersect(pick.neutralised, other.neutralised);
    const fields = pick.fields === other.fields ? pick.fields : undefined;
    const structured = pick.structured || other.structured;
    const markup = pick.markup || other.markup;
    if (neutralised === pick.neutralised && fields === pick.fields && structured === pick.structured && markup === pick.markup) return pick;
    return { ...pick, neutralised, fields, structured, markup };
  }

  /**
   * Merges the state at the end of each branch back into `scope`. A variable is
   * tainted afterwards if it is tainted at the end of any branch that reaches
   * the following code; branches that return or throw contribute nothing.
   * Branches that `break` / `continue` contribute what they assigned, because
   * that value is still live after the loop. `includeEntry` adds the path on
   * which no branch ran at all (a loop body that never executes).
   */
  private join(scope: Scope, branches: Branch[], includeEntry = false) {
    const live = branches.filter((b) => b.exit === "none");
    const escaping = branches.filter((b) => b.exit === "break" || b.exit === "continue");
    const names = new Set<string>();
    for (const b of live) for (const n of b.fork.touched()) names.add(n);
    for (const b of escaping) for (const n of b.fork.touched()) if (b.fork.wrote(n)) names.add(n);

    const updates: Array<[string, Taint | null]> = [];
    for (const n of names) {
      const entry = scope.lookup(n);
      let t: Taint | null = includeEntry || !live.length ? entry : null;
      for (const b of live) t = this.union(t, b.fork.touches(n) ? b.fork.branchValue(n) : entry);
      for (const b of escaping) if (b.fork.wrote(n)) t = this.union(t, b.fork.branchValue(n));
      updates.push([n, t]);
    }
    for (const [n, t] of updates) if (t !== scope.lookup(n)) scope.assign(n, t);

    // An expression validated on every path that reaches here stays validated.
    if (live.length && !includeEntry) {
      const [first, ...rest] = live;
      for (const text of first.fork.cleanTexts()) if (rest.every((b) => b.fork.cleanTexts().includes(text))) scope.markClean(text);
    }
  }

  /**
   * Analyses a loop body. It runs twice so that a value assigned late in the
   * body is seen by the code above it on the next iteration; the state after
   * the loop is the join of "never ran" and "ran".
   */
  private loop(scope: Scope, body: ts.Statement, bind?: (inner: Scope) => void, after?: (inner: Scope) => void) {
    const passes = this.loopDepth >= 3 ? 1 : 2;
    this.loopDepth++;
    for (let pass = 0; pass < passes; pass++) {
      const fork = new Scope(scope, true);
      bind?.(fork);
      this.visit(body, fork);
      after?.(fork);
      this.join(scope, [{ fork, exit: "none" }], true);
    }
    this.loopDepth--;
  }

  private collectFunctions(): Map<string, FunctionLike> {
    const out = new Map<string, FunctionLike>();
    const visit = (node: ts.Node) => {
      // CommonJS: exports.fn = function () {} / module.exports.fn = () => {}
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && (ts.isArrowFunction(node.right) || ts.isFunctionExpression(node.right))) {
        const target = this.calleeText(node.left);
        const m = /^(?:module\.)?exports\.([\w$]+)$/.exec(target);
        if (m) out.set(`exports.${m[1]}`, node.right);
      }
      if (ts.isFunctionDeclaration(node) && node.name && node.body) out.set(node.name.text, node);
      else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
        out.set(node.name.text, node.initializer);
      } else if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.body) out.set(`${classContext(node) ?? ""}#${node.name.text}`, node);
      ts.forEachChild(node, visit);
    };
    visit(this.sf);
    return out;
  }

  private summarise(name: string, fn: FunctionLike) {
    const summary: FunctionSummary = { name: name.replace(/^#/, "").replace("#", "."), returns: new Set(), returnsMarkup: new Set(), sinks: [] };
    const scope = new Scope(undefined, false, true);
    fn.parameters.forEach((p, index) => {
      const taint: Taint = {
        origin: { kind: "param", index },
        steps: [this.step("propagation", p, `enters ${name.replace(/^#/, "").replace("#", ".")}() as parameter ${index + 1}`)],
        confidence: 1,
        structured: true,
      };
      this.bindPattern(p.name, taint, scope);
    });
    const prev = this.currentSummary;
    const prevFrame = this.summaryFrame;
    this.currentSummary = summary;
    this.summaryKeys = new Set();
    this.frames.push({ returned: null });
    this.summaryFrame = this.frames.length;
    this.visitFunctionBody(fn, scope);
    this.frames.pop();
    this.summaryFrame = prevFrame;
    this.currentSummary = prev;
    this.summaries.set(name, summary);
  }

  // ─── sources & sinks ──────────────────────────────────────────────────────

  /** Rewrites a request alias (`r.json`, `request.query` under another name) to the canonical `req.…`. */
  private canonical(text: string, scope: Scope): string {
    const m = /^[A-Za-z_$][\w$]*/.exec(text);
    return m && !/^(?:req|request)$/.test(m[0]) && scope.isAlias(m[0]) ? `req${text.slice(m[0].length)}` : text;
  }

  private sourceFromMember(node: ts.Expression, scope: Scope): Taint | null {
    const text = this.canonical(this.calleeText(node), scope);
    for (const src of SOURCE_MEMBERS) {
      if (src.pattern.test(text)) {
        const whole = /\.(?:body|query|params)\b/.test(text);
        return { origin: { kind: "source" }, steps: [this.step("source", node, src.label)], confidence: 0.95, structured: whole };
      }
    }
    return null;
  }

  private sourceFromCall(rawCallee: string, node: ts.CallExpression, scope: Scope): Taint | null {
    const callee = this.canonical(rawCallee, scope);
    for (const src of SOURCE_CALLS) {
      if (src.pattern.test(callee)) {
        const whole = /\.(?:json|formData)$/.test(callee);
        return { origin: { kind: "source" }, steps: [this.step("source", node, src.label)], confidence: 0.95, structured: whole };
      }
    }
    return null;
  }

  private siteOf(node: ts.Node): SinkSite {
    const start = this.sf.getLineAndCharacterOfPosition(node.getStart(this.sf));
    const end = this.sf.getLineAndCharacterOfPosition(node.getEnd());
    return {
      file: this.file,
      location: { line: start.line + 1, column: start.character + 1, endLine: end.line + 1, endColumn: end.character + 1 },
      snippet: this.sf.text.split("\n")[start.line] ?? this.snippet(node),
    };
  }

  private emit(hit: SinkHit, site: SinkSite) {
    if (this.mode === "summary") {
      this.pushSummarySink({ ...hit, site });
      return;
    }
    const crossFile = site.file !== this.file;
    const label = hit.note ?? `reaches ${hit.sink.title.toLowerCase()} sink`;
    const sinkStep: TraceStep = { kind: "sink", line: site.location.line, label, snippet: site.snippet.trim().slice(0, 90), ...(crossFile ? { file: site.file } : {}) };
    // Steps produced in this file get labelled when the finding is reported in another file.
    const steps = [...hit.steps.map((st) => (crossFile && !st.file ? { ...st, file: this.file } : st)), sinkStep];
    const key = `${hit.sink.id}:${site.file}:${site.location.line}:${site.location.column}`;
    if (this.reported.has(key)) return;
    this.reported.add(key);

    const source = steps[0];
    const origin = crossFile ? ` (from ${source.file ?? this.file})` : "";
    this.findings.push(
      makeFinding({
        rule: { ...hit.sink, title: hit.sink.title },
        file: site.file,
        location: site.location,
        snippet: site.snippet,
        confidence: hit.sink.confidence * hit.confidence,
        detector: "taint",
        trace: steps,
        severity: hit.severityOverride,
        title: `${hit.sink.title}: ${source.label}${origin} → line ${site.location.line}`,
        description: hit.note ? `${hit.sink.description} ${hit.note}.` : hit.sink.description,
      })
    );
  }

  /** Records a parameter-to-sink flow on the function being summarised (loops visit their body twice). */
  private pushSummarySink(hit: SinkHit) {
    const key = `${hit.sink.id}:${hit.sink.title}:${hit.paramIndex}:${hit.site?.file}:${hit.site?.location.line}:${hit.site?.location.column}`;
    if (this.summaryKeys.has(key)) return;
    this.summaryKeys.add(key);
    this.currentSummary?.sinks.push(hit);
  }

  private checkSink(sink: SinkSpec, taint: Taint | null, argNode: ts.Expression, at: ts.Node | SinkSite, why?: string) {
    if (!taint) return;
    if (taint.neutralised?.has(sink.id)) return;
    if (sink.id === "AEG-TAINT-NOSQL" && !taint.structured) return;
    // "/users/" + id can only ever be a path on this site.
    if (sink.id === "AEG-TAINT-REDIRECT" && hasLocalPathPrefix(argNode)) return;
    let severityOverride: SinkSpec["severity"] | undefined;
    let note: string | undefined = why;
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
    this.emit(hit, "kind" in at ? this.siteOf(at) : at);
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
      const outerFields = this.thisFields;
      this.thisFields = new Map();
      // Two passes: a field written in one method and read in another is found regardless of method order.
      for (let pass = 0; pass < 2; pass++) {
        for (const member of node.members) {
          if ((ts.isMethodDeclaration(member) || ts.isConstructorDeclaration(member) || ts.isGetAccessor(member) || ts.isSetAccessor(member)) && member.body) {
            if (this.mode === "report") this.visitFunction(member as FunctionLike, scope);
          } else if (ts.isPropertyDeclaration(member) && member.initializer) {
            this.evalExpr(member.initializer, scope);
          }
        }
      }
      this.thisFields = outerFields;
      return;
    }
    if (ts.isBlock(node)) {
      const inner = new Scope(scope);
      for (const s of node.statements) this.visit(s, inner);
      return;
    }
    if (ts.isIfStatement(node)) {
      this.visitIf(node, scope);
      return;
    }
    if (ts.isReturnStatement(node)) {
      if (node.expression) {
        const t = this.evalExpr(node.expression, scope);
        this.recordReturn(t);
      }
      return;
    }
    if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      const iter = this.evalExpr(node.expression, scope);
      const init = node.initializer;
      const element = iter ? this.extend({ ...iter, fields: undefined }, this.step("propagation", init, "loop variable")) : null;
      this.loop(scope, node.statement, (inner) => {
        if (ts.isVariableDeclarationList(init)) {
          for (const d of init.declarations) this.bindPattern(d.name, element, inner);
        } else {
          this.assignTo(init, element, inner);
        }
      });
      return;
    }
    if (ts.isForStatement(node)) {
      const outer = new Scope(scope);
      const init = node.initializer;
      if (init && ts.isVariableDeclarationList(init)) for (const d of init.declarations) this.visitDeclaration(d, outer);
      else if (init) this.evalExpr(init, outer);
      if (node.condition) this.evalExpr(node.condition, outer);
      this.loop(outer, node.statement, undefined, (inner) => {
        if (node.incrementor) this.evalExpr(node.incrementor, inner);
      });
      return;
    }
    if (ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      this.evalExpr(node.expression, scope);
      this.loop(scope, node.statement);
      return;
    }
    if (ts.isSwitchStatement(node)) {
      this.visitSwitch(node, scope);
      return;
    }
    if (ts.isTryStatement(node)) {
      this.visitTry(node, scope);
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

  // ─── validation guards ────────────────────────────────────────────────────

  /**
   * Allowlist / validation checks act as sanitisers on the branch where they hold:
   *   if (!ALLOWED.has(url.hostname)) return;   → `url` is clean afterwards
   *   if (!/^\d+$/.test(id)) throw ...;          → `id` is clean afterwards
   *   if (isUuid(id)) { db.query(...id...) }     → `id` is clean inside the block
   */
  private visitIf(node: ts.IfStatement, scope: Scope) {
    this.evalExpr(node.expression, scope);
    const guard = this.guardOf(node.expression, scope);

    const thenFork = this.guardedScope(scope, guard, true);
    this.visit(node.thenStatement, thenFork);
    // Without an `else`, the other path is "the condition was false": nothing runs, but the guard still holds.
    const elseFork = this.guardedScope(scope, guard, false);
    if (node.elseStatement) this.visit(node.elseStatement, elseFork);

    this.join(scope, [
      { fork: thenFork, exit: exitKind(node.thenStatement) },
      { fork: elseFork, exit: exitKind(node.elseStatement) },
    ]);
  }

  /**
   * Each `case` is a branch. A clause that ends without `break` falls through,
   * so the next clause starts from its state; without a `default`, the path
   * where nothing matched is joined in as well.
   */
  private visitSwitch(node: ts.SwitchStatement, scope: Scope) {
    this.evalExpr(node.expression, scope);
    const branches: Branch[] = [];
    let hasDefault = false;
    let fallthrough: Scope | null = null;
    const clauses = node.caseBlock.clauses;
    clauses.forEach((clause, i) => {
      if (ts.isDefaultClause(clause)) hasDefault = true;
      else this.evalExpr(clause.expression, scope);
      const fork = new Scope(scope, true);
      if (fallthrough) fork.inherit(fallthrough, (a, b) => this.union(a, b));
      // `case "name":` pins the switched value to a constant, exactly like `x === "name"`.
      if (ts.isCaseClause(clause) && (ts.isStringLiteralLike(clause.expression) || ts.isNumericLiteral(clause.expression))) {
        const pinned = this.subjectsOf(node.expression, scope);
        for (const n of pinned.names) fork.refine(n);
        for (const t of pinned.texts) fork.markClean(t);
      }
      for (const stmt of clause.statements) this.visit(stmt, fork);
      let exit: ExitKind = "none";
      for (const stmt of clause.statements) if ((exit = exitKind(stmt)) !== "none") break;
      const last = i === clauses.length - 1;
      fallthrough = exit === "none" && !last ? fork : null;
      // `break` leaves the switch, so that state carries on to the code after it.
      if (exit === "break" || (exit === "none" && last)) branches.push({ fork, exit: "none" });
      else if (exit !== "none") branches.push({ fork, exit });
    });
    this.join(scope, branches, !hasDefault);
  }

  /**
   * The `try` block may stop at any statement, so `catch` starts from a state in
   * which each of its assignments may or may not have happened. Whatever is
   * true after both is true for `finally` and the code that follows.
   */
  private visitTry(node: ts.TryStatement, scope: Scope) {
    const tryFork = new Scope(scope, true);
    this.visit(node.tryBlock, tryFork);
    const branches: Branch[] = [{ fork: tryFork, exit: exitKind(node.tryBlock) }];
    if (node.catchClause) {
      const catchFork = new Scope(scope, true);
      catchFork.inherit(tryFork, (a, b) => this.union(a, b));
      if (node.catchClause.variableDeclaration) this.bindPattern(node.catchClause.variableDeclaration.name, null, catchFork);
      this.visit(node.catchClause.block, catchFork);
      branches.push({ fork: catchFork, exit: exitKind(node.catchClause.block) });
    }
    this.join(scope, branches);
    if (node.finallyBlock) this.visit(node.finallyBlock, scope);
  }

  /** A branch scope in which the guard's subjects are clean, for the branch where `cond === branch`. */
  private guardedScope(scope: Scope, guard: Guard | null, branch: boolean): Scope {
    const inner = new Scope(scope, true);
    if (guard && guard.whenTrue === branch) {
      for (const n of guard.names) inner.refine(n);
      for (const t of guard.texts) inner.markClean(t);
    }
    return inner;
  }

  /** What a validated expression proves safe: a local variable, or (for request fields etc.) the expression itself. */
  private subjectsOf(expr: ts.Expression, scope: Scope): Pick<Guard, "names" | "texts"> {
    let e = expr;
    for (;;) {
      if (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e)) e = e.expression;
      else if (ts.isCallExpression(e) && ts.isIdentifier(e.expression) && e.expression.text === "String" && e.arguments.length === 1) e = e.arguments[0];
      else break;
    }
    if (ts.isIdentifier(e)) return { names: [e.text], texts: [] };
    // Checking a message's origin is what makes its payload trustworthy: `if (e.origin !== APP) return;`.
    if (ts.isPropertyAccessExpression(e) && e.name.text === "origin" && ts.isIdentifier(e.expression)) {
      return { names: [], texts: [`${e.expression.text}.data`, this.calleeText(e)] };
    }
    // A validated request field (req.query.next) clears that field only, never the whole request object.
    const base = baseName(e);
    if (base && scope.has(base) && !this.sourceFromMember(e, scope)) return { names: [base], texts: [] };
    return { names: [], texts: [this.calleeText(e)] };
  }

  private guardOf(cond: ts.Expression, scope: Scope): Guard | null {
    while (ts.isParenthesizedExpression(cond)) cond = cond.expression;

    if (ts.isPrefixUnaryExpression(cond) && cond.operator === ts.SyntaxKind.ExclamationToken) {
      const inner = this.guardOf(cond.operand, scope);
      return inner ? { ...inner, whenTrue: !inner.whenTrue } : null;
    }

    if (ts.isBinaryExpression(cond)) {
      const op = cond.operatorToken.kind;
      if (op === ts.SyntaxKind.AmpersandAmpersandToken || op === ts.SyntaxKind.BarBarToken) {
        const parts = [this.guardOf(cond.left, scope), this.guardOf(cond.right, scope)];
        const isAnd = op === ts.SyntaxKind.AmpersandAmpersandToken;
        // `A && B` true ⇒ both hold, so any side that is safe-when-true counts (union).
        // `A && B` false ⇒ only "at least one fails", so a subject is safe only if every side guards it (intersection).
        // `||` is the mirror image.
        const agreeing = parts.filter((g): g is Guard => !!g && g.whenTrue === isAnd);
        if (agreeing.length) return { names: [...new Set(agreeing.flatMap((g) => g.names))], texts: [...new Set(agreeing.flatMap((g) => g.texts))], whenTrue: isAnd };
        if (parts.every((g) => g && g.whenTrue === !isAnd)) {
          const [l, r] = parts as Guard[];
          const names = l.names.filter((n) => r.names.includes(n));
          const texts = l.texts.filter((t) => r.texts.includes(t));
          if (names.length || texts.length) return { names, texts, whenTrue: !isAnd };
        }
        return null;
      }
      // x === "a" / typeof x === "number"  → x is constrained when true; !== flips it.
      const eq = op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken;
      const neq = op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken;
      if (eq || neq) {
        const literal = (e: ts.Expression) => ts.isStringLiteralLike(e) || ts.isNumericLiteral(e);
        let subject: ts.Expression | null = null;
        if (literal(cond.right)) subject = cond.left;
        else if (literal(cond.left)) subject = cond.right;
        if (!subject) return null;
        if (ts.isTypeOfExpression(subject)) {
          const t = (literal(cond.right) ? cond.right : cond.left) as ts.StringLiteral;
          if (!/^(?:number|boolean|bigint)$/.test(t.text)) return null;
          subject = subject.expression;
        }
        return { ...this.subjectsOf(subject, scope), whenTrue: eq };
      }
      return null;
    }

    if (ts.isCallExpression(cond)) {
      const subjects = this.validatedBy(cond);
      if (!subjects.length) return null;
      const all = subjects.map((e) => this.subjectsOf(e, scope));
      return { names: all.flatMap((x) => x.names), texts: all.flatMap((x) => x.texts), whenTrue: true };
    }
    return null;
  }

  /** Expressions that a validating call proves safe when it returns true. */
  private validatedBy(call: ts.CallExpression): ts.Expression[] {
    const callee = this.calleeText(call.expression);
    const argNames = () => [...call.arguments];

    if (ts.isPropertyAccessExpression(call.expression)) {
      const method = call.expression.name.text;
      const receiver = call.expression.expression;
      // ALLOWED.has(x), ALLOWED.includes(x)
      if ((method === "has" || method === "includes") && call.arguments.length === 1) return argNames();
      // /^[a-z0-9]+$/.test(x) — only anchored patterns constrain the whole value
      if (method === "test" && call.arguments.length === 1) {
        if (ts.isRegularExpressionLiteral(receiver) && !isStrictPattern(receiver.text)) return [];
        return argNames();
      }
      // resolved.startsWith(root) — but a bare protocol check ("https://") proves nothing about the host
      if (method === "startsWith" && call.arguments[0]) {
        const arg = call.arguments[0];
        if (ts.isStringLiteralLike(arg) && /^[a-z][\w+.-]*:(?:\/\/)?$/i.test(arg.text)) return [];
        return [receiver];
      }
    }
    // isUuid(x), isValidId(x), validator.isEmail(x), Number.isInteger(x), validateSlug(x)
    if (/(?:^|\.)(?:is[A-Z]\w*|isValid\w*|validate\w*|Number\.is(?:Integer|SafeInteger|Finite))$/.test(callee)) return argNames();
    return [];
  }

  private visitDeclaration(decl: ts.VariableDeclaration, scope: Scope) {
    if (!decl.initializer) {
      this.bindPattern(decl.name, null, scope);
      return;
    }
    const value = this.evalExpr(decl.initializer, scope);
    const label = ts.isIdentifier(decl.name) ? `assigned to \`${decl.name.text}\`` : "destructured";
    const taint = value ? this.extend(value, this.step("propagation", decl, label)) : null;
    // `var` belongs to the function, not the block: declare it there and assign, so branches join correctly.
    const isVar = ts.isVariableDeclarationList(decl.parent) && !(decl.parent.flags & ts.NodeFlags.BlockScoped);
    if (isVar && ts.isIdentifier(decl.name) && !scope.isFunction) {
      scope.hoist(decl.name.text);
      scope.assign(decl.name.text, taint);
      return;
    }
    this.bindPattern(decl.name, taint, scope);
  }

  private bindPattern(name: ts.BindingName, taint: Taint | null, scope: Scope) {
    if (ts.isIdentifier(name)) {
      scope.declare(name.text, taint);
      return;
    }
    for (const el of name.elements) {
      if (ts.isOmittedExpression(el)) continue;
      // `const { host } = cfg` reads one known field of an object literal.
      const key = ts.isObjectBindingPattern(name) && !el.dotDotDotToken ? propertyKey(el.propertyName ?? el.name) : null;
      const known = taint?.fields && key !== null && taint.fields.has(key);
      this.bindPattern(el.name, known ? (taint!.fields!.get(key!) ?? null) : taint && taint.fields ? { ...taint, fields: undefined } : taint, scope);
    }
  }

  /** Visits a function body in report or summary mode and returns the taint of what it returns. */
  private visitFunction(fn: FunctionLike | ts.ConstructorDeclaration | ts.AccessorDeclaration, outer: Scope, seed?: Taint | null, seedIndex = 0): Taint | null {
    const scope = new Scope(outer, false, true);
    const name = (fn as ts.FunctionDeclaration).name;
    const declared = name && ts.isIdentifier(name) ? name.text : ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name) ? fn.parent.name.text : "";
    const isHandler = HTTP_HANDLER_NAMES.test(declared) || this.isRouterCallback(fn);
    const serverAction = this.isServerAction(fn);
    const resolver = isGraphqlResolver(fn);

    fn.parameters.forEach((p, i) => {
      if (i === seedIndex && seed) {
        this.bindPattern(p.name, this.extend(seed, this.step("propagation", p, "callback parameter")), scope);
        return;
      }
      const type = p.type ? this.text(p.type) : "";
      const primitive = /^(?:number|boolean|bigint|Date)\b/.test(type);
      // GraphQL resolvers are called as (parent, args, context, info); `args` is whatever the client sent.
      if (resolver && i === 1) {
        const t: Taint = { origin: { kind: "source" }, steps: [this.step("source", p, "GraphQL arguments")], confidence: 0.85, structured: true };
        this.bindPattern(p.name, t, scope);
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
      // NestJS: @Query("sort") sort: string — the decorator injects request data.
      const decorator = this.paramDecorator(p);
      if (decorator?.kind === "data" && !primitive) {
        const t: Taint = { origin: { kind: "source" }, steps: [this.step("source", p, `@${decorator.name}() request input`)], confidence: 0.9, structured: decorator.name === "Body" || type !== "string" };
        this.bindPattern(p.name, t, scope);
        return;
      }
      // Server Actions are public endpoints: their arguments come straight from the client.
      if (serverAction && !primitive) {
        const t: Taint = { origin: { kind: "source" }, steps: [this.step("source", p, "Server Action argument")], confidence: 0.85, structured: !/^(?:string|FormData)\b/.test(type) };
        this.bindPattern(p.name, t, scope);
        return;
      }
      this.bindPattern(p.name, null, scope);
      // A request under another name: `POST(r: Request)`, `@Req() incoming`, `(msg: IncomingMessage)`.
      if (ts.isIdentifier(p.name) && (REQUEST_TYPES.test(type) || decorator?.kind === "request" || (i === 0 && VERB_HANDLER_NAMES.test(declared)))) scope.alias(p.name.text);
    });

    this.frames.push({ returned: null });
    this.visitFunctionBody(fn, scope);
    return this.frames.pop()!.returned;
  }

  private paramDecorator(p: ts.ParameterDeclaration): { kind: "data" | "request"; name: string } | null {
    for (const d of (ts.canHaveDecorators(p) && ts.getDecorators(p)) || []) {
      const call = ts.isCallExpression(d.expression) ? d.expression : null;
      const name = this.text(call ? call.expression : d.expression);
      if (REQUEST_DECORATORS.test(name)) return { kind: "request", name };
      if (!PARAM_DECORATORS.test(name)) continue;
      // @Param("id", ParseIntPipe) hands the method a number, not the raw string.
      if (call?.arguments.some((a) => VALIDATING_PIPES.test(this.text(a)))) return null;
      return { kind: "data", name };
    }
    return null;
  }

  /** `"use server"` at the top of the module (for its exports) or of the function body. */
  private isServerAction(fn: ts.Node & { body?: ts.Node }): boolean {
    if (fn.body && ts.isBlock(fn.body) && hasDirective(fn.body.statements, "use server")) return true;
    if (!this.useServerFile) return false;
    const exported = (n: ts.Node) => ts.canHaveModifiers(n) && !!ts.getModifiers(n)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (ts.isFunctionDeclaration(fn)) return exported(fn);
    const decl = fn.parent;
    return (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && !!decl && ts.isVariableDeclaration(decl) && !!decl.parent?.parent && ts.isVariableStatement(decl.parent.parent) && exported(decl.parent.parent);
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
      this.recordReturn(this.evalExpr(body, scope));
    }
  }

  private recordReturn(t: Taint | null) {
    const frame = this.frames[this.frames.length - 1];
    if (frame) frame.returned = this.union(frame.returned, t);
    // A `return` inside a nested callback is that callback's result, not the summarised function's.
    if (!t || t.origin.kind !== "param" || !this.currentSummary || this.frames.length !== this.summaryFrame) return;
    this.currentSummary.returns.add(t.origin.index);
    if (t.markup) this.currentSummary.returnsMarkup.add(t.origin.index);
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
          const rhs = target.parent && ts.isBinaryExpression(target.parent) ? target.parent.right : target;
          if (re.test(targetText)) this.checkSink(sink, value, rhs, target.parent ?? target);
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
      if (ts.isPropertyAccessExpression(target) && target.expression.kind === ts.SyntaxKind.ThisKeyword) {
        if (value) this.thisFields.set(target.name.text, this.extend(value, this.step("propagation", target, `stored in this.${target.name.text}`)));
        else this.thisFields.delete(target.name.text);
        return;
      }
      // Writing a tainted value into an object taints the object itself.
      let base: ts.Expression = target.expression;
      while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) base = base.expression;
      if (!ts.isIdentifier(base)) return;
      const current = scope.lookup(base.text);
      const key = target.expression === base ? accessKey(target) : null;
      if (current?.fields && key !== null) {
        // The object's fields are known, so only the written one changes.
        const fields = new Map(current.fields).set(key, value);
        scope.assign(base.text, { ...(value ? this.union({ ...current, fields: undefined }, value)! : current), fields });
      } else if (value) {
        const merged = this.union(current, value)!;
        scope.assign(base.text, merged.fields ? { ...merged, fields: undefined } : merged);
      }
    }
  }

  // ─── expressions ──────────────────────────────────────────────────────────

  private evalExpr(node: ts.Expression, scope: Scope): Taint | null {
    if (ts.isIdentifier(node)) return scope.lookup(node.text);
    if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node) || ts.isCallExpression(node)) && scope.isClean(this.calleeText(node))) return null;

    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node) || ts.isAwaitExpression(node)) {
      return this.evalExpr(node.expression, scope);
    }
    if (ts.isSpreadElement(node)) return this.evalExpr(node.expression, scope);

    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const src = this.sourceFromMember(node, scope);
      if (src) return src;
      if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
        const field = this.thisFields.get(node.name.text);
        if (field) return field;
      }
      if (ts.isElementAccessExpression(node)) this.evalExpr(node.argumentExpression, scope);
      const obj = this.evalExpr(node.expression, scope);
      if (!obj) return null;
      if (ts.isPropertyAccessExpression(node) && node.name.text === "length") return null;
      // A known field of an object literal carries its own taint; anything else inherits the object's.
      const key = accessKey(node);
      if (obj.fields && key !== null && obj.fields.has(key)) return obj.fields.get(key) ?? null;
      return obj.fields ? { ...obj, fields: undefined } : obj;
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
      const html = HTML_TAG.test(node.head.text) || node.templateSpans.some((sp) => HTML_TAG.test(sp.literal.text));
      return t ? this.extend({ ...t, structured: false, markup: t.markup || html }, this.step("propagation", node, "interpolated into string")) : null;
    }

    if (ts.isBinaryExpression(node)) return this.evalBinary(node, scope);

    if (ts.isConditionalExpression(node)) {
      this.evalExpr(node.condition, scope);
      // isSafe(x) ? x : fallback — each branch is evaluated knowing which way the check went.
      const guard = this.guardOf(node.condition, scope);
      const whenTrue = this.guardedScope(scope, guard, true);
      const whenFalse = this.guardedScope(scope, guard, false);
      const t = this.union(this.evalExpr(node.whenTrue, whenTrue), this.evalExpr(node.whenFalse, whenFalse));
      this.join(scope, [{ fork: whenTrue, exit: "none" }, { fork: whenFalse, exit: "none" }]);
      return t;
    }

    if (ts.isObjectLiteralExpression(node)) {
      let t: Taint | null = null;
      // Field-precise as long as every key is a plain name; a spread or computed key makes the shape unknown.
      let precise = true;
      const fields = new Map<string, Taint | null>();
      for (const p of node.properties) {
        const key = p.name ? propertyKey(p.name) : null;
        let value: Taint | null = null;
        if (ts.isPropertyAssignment(p)) value = this.evalExpr(p.initializer, scope);
        else if (ts.isShorthandPropertyAssignment(p)) value = scope.lookup(p.name.text);
        else if (ts.isSpreadAssignment(p)) value = this.evalExpr(p.expression, scope);
        else if (ts.isMethodDeclaration(p) && this.mode === "report") this.visitFunction(p, scope);
        if (key === null) precise = false;
        else fields.set(key, value);
        t = this.union(t, value);
      }
      return t && precise ? { ...t, fields } : t && t.fields ? { ...t, fields: undefined } : t;
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
    // `isSafe(x) && run(x)`: the right-hand side only runs when the check passed (or, for `||`, failed).
    let right: Taint | null;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken || op === ts.SyntaxKind.BarBarToken) {
      const fork = this.guardedScope(scope, this.guardOf(node.left, scope), op === ts.SyntaxKind.AmpersandAmpersandToken);
      right = this.evalExpr(node.right, fork);
      this.join(scope, [{ fork, exit: "none" }], true);
    } else right = this.evalExpr(node.right, scope);
    switch (op) {
      case ts.SyntaxKind.PlusToken: {
        const t = this.union(left, right);
        const html = [node.left, node.right].some((e) => ts.isStringLiteralLike(e) && HTML_TAG.test(e.text));
        return t ? this.extend({ ...t, structured: false, markup: t.markup || html }, this.step("propagation", node, "concatenated into string")) : null;
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
    if (/^(?:Next)?Response$/.test(callee) && args[1]) this.checkLocation(headerValue(args[1], "headers"), node, scope);
    return null;
  }

  private evalCall(node: ts.CallExpression, scope: Scope): Taint | null {
    const written = this.calleeText(node.expression);
    // `const execAsync = promisify(exec)` and `import { exec as run }` are the same function under another name.
    const callee = (ts.isIdentifier(node.expression) && this.facts.renamed.get(written)) || written;
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

    // Callbacks on tainted collections receive tainted elements (the accumulator comes first in reduce).
    let callbackResult: Taint | null | undefined;
    const argTaints = args.map((a, i) => {
      if ((ts.isArrowFunction(a) || ts.isFunctionExpression(a)) && i === 0 && receiver && ARRAY_CALLBACK_METHODS.has(method)) {
        const element = receiver.fields ? { ...receiver, fields: undefined } : receiver;
        callbackResult = this.visitFunction(a, scope, element, method === "reduce" || method === "reduceRight" ? 1 : 0);
        return null;
      }
      return this.evalExpr(a, scope);
    });

    // Function summaries: local functions first, then functions imported from other project files.
    const local = this.localSummary(node.expression, written);
    const external = local ? undefined : this.externalSummary(node.expression);
    const summary = local ?? external;

    if (!summary) {
      this.checkShellSpawn(callee, node, scope);
      this.checkWhere(callee, node, scope);
      this.checkQueryBuilder(callee, node, argTaints[0] ?? null);
      this.checkLocation(this.locationHeader(callee, node), node, scope);
    }

    // Sinks — skipped for calls into the project's own code (a helper named `execute` is not a DB driver).
    for (const sink of summary ? [] : SINKS) {
      if (sink.isNew || !sink.callee.test(callee)) continue;
      if (sink.id === "AEG-TAINT-CODE" && /setTimeout|setInterval/.test(callee) && args[0] && (ts.isArrowFunction(args[0]) || ts.isFunctionExpression(args[0]))) continue;
      const idx = sink.args === "any" ? args.map((_, i) => i) : sink.args;
      for (const i of idx) if (args[i]) this.checkSink(sink, argTaints[i], args[i], node);
    }
    if (RESPONSE_WRITERS.test(callee) && args[0]) this.checkReflected(args[0], argTaints[0], node);

    if (summary && summary !== this.currentSummary) {
      const where = external ? ` in ${external.file}` : "";
      for (const hit of summary.sinks) {
        const actual = argTaints[hit.paramIndex];
        if (!actual) continue;
        const joined: Taint = {
          ...actual,
          steps: [...actual.steps, this.step("propagation", node, `passed to ${summary.name}()${where}`), ...hit.steps.slice(1)],
          confidence: actual.confidence * hit.confidence * 0.95,
        };
        const argNode = args[hit.paramIndex];
        if (actual.origin.kind === "param") {
          if (this.mode === "summary" && !actual.neutralised?.has(hit.sink.id)) this.pushSummarySink({ ...hit, paramIndex: actual.origin.index, steps: joined.steps, confidence: joined.confidence });
        } else {
          this.checkSink(hit.sink, joined, argNode, hit.site ?? node);
        }
      }
      let ret: Taint | null = null;
      const returns = [...summary.returns];
      const markup = [...summary.returnsMarkup].some((i) => !!argTaints[i]);
      for (const i of returns) ret = this.union(ret, argTaints[i] ?? null);
      return ret ? this.extend({ ...ret, markup: ret.markup || markup }, this.step("propagation", node, `returned from ${summary.name}()${where}`)) : null;
    }

    const source = this.sourceFromCall(callee, node, scope);
    if (source) return source;

    // Schema.parse(input): the result has the shape the schema allows, not the shape the client sent.
    if (/^(?:parse|parseAsync|safeParse|safeParseAsync)$/.test(method) && ts.isPropertyAccessExpression(node.expression)) {
      const shape = schemaShape(node.expression.expression, this.facts.schemas);
      if (shape) {
        const input = argTaints[0] ? this.extend({ ...argTaints[0], structured: false, fields: undefined }, this.step("propagation", node, `validated by ${written}()`)) : null;
        const parsed = applyShape(shape, input);
        if (!parsed || !method.startsWith("safeParse")) return parsed;
        return { ...parsed, fields: new Map<string, Taint | null>([["data", parsed], ["success", null], ["error", null]]) };
      }
    }

    const everything = argTaints.reduce<Taint | null>((acc, t) => this.union(acc, t), receiver);
    const cleans = sanitizerScope(callee);
    if (cleans === "all") return null;
    if (cleans) return this.neutralise(everything, cleans, node, callee);

    if (receiver && (method === "map" || method === "flatMap") && args[0]) {
      // arr.map((x) => Number(x)): the result is whatever the callback returns, not the original elements.
      if (callbackResult !== undefined) return callbackResult ? this.extend({ ...callbackResult, fields: undefined }, this.step("propagation", node, `through .${method}()`)) : null;
      // arr.map(Number) / arr.map(escapeHtml): every element passes through a sanitiser.
      const each = ts.isArrowFunction(args[0]) || ts.isFunctionExpression(args[0]) ? null : sanitizerScope(this.calleeText(args[0]));
      if (each === "all") return null;
      if (each) return this.neutralise(receiver, each, node, this.calleeText(args[0]));
    }
    if (receiver && (method === "reduce" || method === "reduceRight") && callbackResult !== undefined) {
      const result = this.union(callbackResult, argTaints[1] ?? null);
      return result ? this.extend({ ...result, fields: undefined }, this.step("propagation", node, `through .${method}()`)) : null;
    }

    if (receiver) {
      const factor = PASSTHROUGH_METHODS.has(method) ? 1 : 0.85;
      return this.extend({ ...receiver, structured: method === "json" || method === "formData" ? receiver.structured : false }, this.step("propagation", node, `through .${method || "call"}()`), factor);
    }

    const argTaint = argTaints.reduce<Taint | null>((acc, t) => this.union(acc, t), null);
    if (!argTaint) return null;
    // Decoding undoes whatever escaping happened earlier in the flow.
    if (DECODERS.test(callee)) return this.extend({ ...argTaint, structured: false, neutralised: undefined, fields: undefined }, this.step("propagation", node, `through ${callee}()`));
    if (ARG_PASSTHROUGH.test(callee)) return this.extend({ ...argTaint, structured: false, fields: undefined }, this.step("propagation", node, `through ${callee}()`));
    // Unknown function: assume the value flows through, with reduced confidence.
    return this.extend({ ...argTaint, structured: false, fields: undefined }, this.step("propagation", node, `through ${callee}()`), 0.75);
  }

  /** The value survives a context-specific escaper: safe for those sinks, unchanged for the rest. */
  private neutralise(t: Taint | null, sinks: readonly string[], node: ts.Node, callee: string): Taint | null {
    if (!t) return null;
    const neutralised = new Set([...(t.neutralised ?? []), ...sinks]);
    return this.extend({ ...t, structured: false, fields: undefined, neutralised }, this.step("propagation", node, `escaped by ${callee}() for ${sinks.map((id) => SINK_CONTEXT[id] ?? id).join(" / ")} only`));
  }

  /**
   * `spawn("sh", ["-c", cmd])` and `spawn(bin, args, { shell: true })` hand the
   * argument array to a shell, so a tainted element is command injection even
   * though the usual argument-array form is safe.
   */
  private checkShellSpawn(callee: string, node: ts.CallExpression, scope: Scope) {
    if (!/(?:^|\.)(?:spawn|spawnSync|execFile|execFileSync|execa|execaSync)$/.test(callee)) return;
    const [bin, list, opts] = node.arguments;
    if (!bin || !list || !ts.isArrayLiteralExpression(list)) return;
    const shellBinary = ts.isStringLiteralLike(bin) && /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i.test(bin.text);
    const shellOption =
      !!opts &&
      ts.isObjectLiteralExpression(opts) &&
      opts.properties.some((p) => ts.isPropertyAssignment(p) && propertyKey(p.name) === "shell" && p.initializer.kind !== ts.SyntaxKind.FalseKeyword);
    if (!shellBinary && !shellOption) return;
    const sink = SINKS.find((s) => s.id === "AEG-TAINT-CMD")!;
    list.elements.forEach((el, i) => {
      const prev = list.elements[i - 1];
      const afterFlag = !!prev && ts.isStringLiteralLike(prev) && /^(?:-[a-z]*c|\/c|-command|-encodedcommand)$/i.test(prev.text);
      if (shellBinary && !shellOption && !afterFlag) return;
      this.checkSink(sink, this.evalExpr(el, scope), el, node, shellOption ? "the arguments are joined and parsed by a shell (shell: true)" : "the string after -c is run by a shell");
    });
  }

  /** MongoDB's `$where` evaluates a JavaScript string on the server, so a concatenated value is code injection. */
  private checkWhere(callee: string, node: ts.CallExpression, scope: Scope) {
    const sink = SINKS.find((s) => s.id === "AEG-TAINT-NOSQL")!;
    if (!sink.callee.test(callee)) return;
    const first = node.arguments[0];
    if (!first) return;
    const exprs = /\.\$where$/.test(callee)
      ? [first]
      : ts.isObjectLiteralExpression(first)
        ? first.properties.flatMap((p) => (ts.isPropertyAssignment(p) && propertyKey(p.name) === "$where" ? [p.initializer] : []))
        : [];
    for (const e of exprs) {
      const t = this.evalExpr(e, scope);
      if (!t) continue;
      this.checkSink(
        { ...sink, title: "NoSQL injection via $where", severity: "critical", confidence: 0.85, description: "Untrusted input is concatenated into a MongoDB $where expression, which the server evaluates as JavaScript." },
        { ...t, structured: true },
        e,
        node
      );
    }
  }

  /** Resolves `fn(...)`, `ns.fn(...)` or `defaultImport(...)` against imported module summaries. */
  private externalSummary(expr: ts.Expression): ExportedSummary | undefined {
    if (ts.isIdentifier(expr)) {
      const b = this.imports.get(expr.text);
      if (!b) return undefined;
      return b.kind === "fn" ? b.summary : b.members.get("default");
    }
    if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
      const b = this.imports.get(expr.expression.text);
      if (b?.kind === "ns") return b.members.get(expr.name.text);
    }
    // users.findByName(...) where `users` is an instance of an imported class.
    if (ts.isPropertyAccessExpression(expr)) {
      const cls = this.classOf(expr.expression);
      const b = cls ? this.imports.get(cls) : undefined;
      if (b?.kind === "ns") return b.members.get(expr.name.text);
    }
    return undefined;
  }

  /** A function, `exports.fn`, or a method of a class declared in this file. */
  private localSummary(expr: ts.Expression, callee: string): FunctionSummary | undefined {
    if (ts.isIdentifier(expr)) return this.summaries.get(expr.text);
    const direct = this.summaries.get(callee);
    if (direct) return direct;
    if (!ts.isPropertyAccessExpression(expr)) return undefined;
    const cls = this.classOf(expr.expression);
    return cls === null ? undefined : this.summaries.get(`${cls}#${expr.name.text}`);
  }

  /**
   * The class an expression is an instance of, when the code says so: `this`,
   * `new C()`, a variable or parameter declared as `C`, or a field declared as
   * `C` (including constructor parameter properties, the usual way services
   * are injected).
   */
  private classOf(expr: ts.Expression): string | null {
    let e = expr;
    while (ts.isParenthesizedExpression(e) || ts.isAwaitExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e)) e = e.expression;
    if (e.kind === ts.SyntaxKind.ThisKeyword) return classContext(e);
    if (ts.isNewExpression(e) && ts.isIdentifier(e.expression)) return e.expression.text;
    if (ts.isIdentifier(e)) return this.facts.classes.has(e.text) ? e.text : (this.facts.instances.get(e.text) ?? null);
    if (ts.isPropertyAccessExpression(e) && e.expression.kind === ts.SyntaxKind.ThisKeyword) return this.facts.fields.get(`${classContext(e) ?? ""}#${e.name.text}`) ?? null;
    return null;
  }

  /** `.where("name = '" + x + "'")` on a query builder is raw SQL; `.where("name", x)` and `.where({ name: x })` are not. */
  private checkQueryBuilder(callee: string, node: ts.CallExpression, taint: Taint | null) {
    if (!taint || !/\.(?:where|andWhere|orWhere|having|andHaving|orHaving)$/.test(callee)) return;
    const first = node.arguments[0];
    const built = ts.isTemplateExpression(first) || (ts.isBinaryExpression(first) && first.operatorToken.kind === ts.SyntaxKind.PlusToken);
    if (!built) return;
    const sink = SINKS.find((s) => s.id === "AEG-TAINT-SQL")!;
    this.checkSink({ ...sink, title: "SQL injection in a query-builder condition", confidence: 0.8 }, taint, first, node);
  }

  /** The expression used as a `Location` header by `res.writeHead`, `res.setHeader` and friends. */
  private locationHeader(callee: string, node: ts.CallExpression): ts.Expression | undefined {
    const m = /^(?:res|reply|response|ctx)\.(writeHead|setHeader|header|set|append|location)$/.exec(callee);
    if (!m) return undefined;
    const args = node.arguments;
    if (m[1] === "location") return args[0];
    if (m[1] === "writeHead") return args.map((a) => headerValue(a)).find(Boolean);
    return args[0] && ts.isStringLiteralLike(args[0]) && /^location$/i.test(args[0].text) ? args[1] : undefined;
  }

  private checkLocation(target: ts.Expression | undefined, node: ts.Node, scope: Scope) {
    if (!target) return;
    const sink = SINKS.find((s) => s.id === "AEG-TAINT-REDIRECT")!;
    this.checkSink(sink, this.evalExpr(target, scope), target, node, "sent as the Location header");
  }

  /** Reflected XSS: tainted data concatenated into an HTML string sent as a response. */
  private checkReflected(arg: ts.Expression, taint: Taint | null, node: ts.Node) {
    if (!taint) return;
    if (!taint.markup && !HTML_TAG.test(this.text(arg))) return;
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

/** The identifier a guarded expression is rooted at: `url.hostname` → `url`, `req.query.id` → null (not a local). */
function baseName(expr: ts.Expression): string | null {
  let e = expr;
  while (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e) || ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e) || ts.isAsExpression(e)) e = e.expression;
  return ts.isIdentifier(e) ? e.text : null;
}

/** The class (or object literal, as "") whose `this` is in effect at `node`; null outside any. */
function classContext(node: ts.Node): string | null {
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (ts.isClassDeclaration(n) || ts.isClassExpression(n)) {
      if (n.name) return n.name.text;
      return ts.isVariableDeclaration(n.parent) && ts.isIdentifier(n.parent.name) ? n.parent.name.text : "";
    }
    if (ts.isObjectLiteralExpression(n) && ts.isMethodDeclaration(node)) return "";
    if (ts.isMethodDeclaration(n) && ts.isObjectLiteralExpression(n.parent)) return "";
    // A plain function has its own `this`.
    if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n)) return null;
  }
  return null;
}

/** `{ Query: { user: (parent, args) => … } }` — a GraphQL resolver map. */
function isGraphqlResolver(fn: ts.Node): boolean {
  const member = ts.isMethodDeclaration(fn) ? fn : fn.parent && ts.isPropertyAssignment(fn.parent) ? fn.parent : null;
  const map = member?.parent;
  const owner = map && ts.isObjectLiteralExpression(map) ? map.parent : null;
  return !!owner && ts.isPropertyAssignment(owner) && /^(?:Query|Mutation|Subscription)$/.test(propertyKey(owner.name) ?? "");
}

/** True for `"/users/" + id` and `` `/users/${id}` ``: a fixed, single-slash path prefix. */
function hasLocalPathPrefix(node: ts.Expression): boolean {
  let e = node;
  while (ts.isParenthesizedExpression(e)) e = e.expression;
  let head: string | null = null;
  if (ts.isTemplateExpression(e)) head = e.head.text;
  else {
    while (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) e = e.left;
    if (ts.isStringLiteralLike(e) && e !== node) head = e.text;
  }
  return head !== null && /^\/[^/\\]/.test(head);
}

/** The `Location` entry of a headers object literal, optionally nested under `key` (`{ headers: { Location } }`). */
function headerValue(node: ts.Expression, key?: string): ts.Expression | undefined {
  if (!ts.isObjectLiteralExpression(node)) return undefined;
  for (const p of node.properties) {
    if (!ts.isPropertyAssignment(p)) continue;
    const name = propertyKey(p.name) ?? "";
    if (key ? name === key : /^location$/i.test(name)) return key ? headerValue(p.initializer) : p.initializer;
  }
  return undefined;
}

/** What a Zod schema lets through: nothing attacker-shaped ("clean"), free text ("raw"), or an object of those. */
type Shape = "clean" | "raw" | Map<string, Shape>;

const ZOD_CONSTRAINED = /^(?:z|zod)\.(?:coerce\.)?(?:number|boolean|bigint|date|int|int32|float32|float64|enum|nativeEnum|literal|uuid|guid|cuid2?|ulid|nanoid|ipv4|ipv6|iso)\b/;
const ZOD_STRING_FORMAT = /^(?:z|zod)\.string\(\)[\s\S]*\.(?:uuid|guid|cuid2?|ulid|nanoid|datetime|date|time|ip|ipv4|ipv6)\(/;

function zodShape(expr: ts.Expression): Shape | null {
  // Walk back through .optional() / .strict() / .default(…) to the constructor call.
  let e = expr;
  for (;;) {
    if (!ts.isCallExpression(e)) return null;
    const text = e.expression.getText().replace(/\s+/g, "");
    if (/^(?:z|zod)\.(?:object|strictObject|looseObject)$/.test(text)) {
      const arg = e.arguments[0];
      if (!arg || !ts.isObjectLiteralExpression(arg)) return null;
      const fields = new Map<string, Shape>();
      for (const p of arg.properties) {
        const key = p.name ? propertyKey(p.name) : null;
        if (key === null || !ts.isPropertyAssignment(p)) return null;
        fields.set(key, zodShape(p.initializer) ?? "raw");
      }
      return fields;
    }
    if (/^(?:z|zod)\.array$/.test(text)) return e.arguments[0] ? zodShape(e.arguments[0]) : null;
    if (/^(?:z|zod)\./.test(text)) {
      const whole = expr.getText().replace(/\s+/g, "");
      if (ZOD_CONSTRAINED.test(whole) || ZOD_STRING_FORMAT.test(whole)) return "clean";
      const pattern = /\.regex\((\/(?:[^/\\\n]|\\.)+\/[a-z]*)/.exec(expr.getText());
      return pattern && isStrictPattern(pattern[1]) ? "clean" : "raw";
    }
    if (!ts.isPropertyAccessExpression(e.expression)) return null;
    e = e.expression.expression;
  }
}

/** The schema an expression refers to: a declared `const Query = z.object(…)` or an inline one. */
function schemaShape(expr: ts.Expression, declared: Map<string, Shape>): Shape | null {
  if (ts.isIdentifier(expr)) return declared.get(expr.text) ?? null;
  return zodShape(expr);
}

function applyShape(shape: Shape, input: Taint | null): Taint | null {
  if (!input || shape === "clean") return null;
  if (shape === "raw") return input;
  const fields = new Map<string, Taint | null>();
  for (const [key, sub] of shape) fields.set(key, applyShape(sub, input));
  return [...fields.values()].some(Boolean) ? { ...input, fields } : null;
}

interface FileFacts {
  /** Classes declared in this file. */
  classes: Set<string>;
  /** Variable or parameter name → the class it is declared as (`new C()` or `: C`). */
  instances: Map<string, string>;
  /** `Class#field` → the class that field is declared as. */
  fields: Map<string, string>;
  /** Local name → the function it really is (`promisify(exec)`, `import { exec as run }`). */
  renamed: Map<string, string>;
  schemas: Map<string, Shape>;
}

/** One pass over the declarations. Flow-insensitive on purpose: it only decides which summary a call resolves to. */
function collectFacts(sf: ts.SourceFile): FileFacts {
  const facts: FileFacts = { classes: new Set(), instances: new Map(), fields: new Map(), renamed: new Map(), schemas: new Map() };
  const typeName = (t: ts.TypeNode | undefined) => (t && ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) ? t.typeName.text : null);
  const constructed = (e: ts.Expression | undefined) => (e && ts.isNewExpression(e) && ts.isIdentifier(e.expression) ? e.expression.text : null);
  const external = (spec: ts.Expression) => ts.isStringLiteral(spec) && !/^[./]/.test(spec.text);

  const visit = (node: ts.Node) => {
    if ((ts.isClassDeclaration(node) || ts.isClassExpression(node)) && node.name) facts.classes.add(node.name.text);
    else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const init = node.initializer;
      const cls = constructed(init) ?? typeName(node.type);
      if (cls) facts.instances.set(node.name.text, cls);
      if (init && ts.isClassExpression(init)) facts.classes.add(node.name.text);
      if (init && ts.isCallExpression(init) && /^(?:util\.)?promisify$/.test(init.expression.getText(sf)) && init.arguments[0]) {
        facts.renamed.set(node.name.text, init.arguments[0].getText(sf).replace(/\s+/g, ""));
      }
      const shape = init ? zodShape(init) : null;
      if (shape) facts.schemas.set(node.name.text, shape);
    } else if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) && node.initializer && ts.isCallExpression(node.initializer) && node.initializer.expression.getText(sf) === "require" && node.initializer.arguments[0] && external(node.initializer.arguments[0])) {
      // const { exec: run } = require("child_process")
      for (const el of node.name.elements) if (el.propertyName && ts.isIdentifier(el.propertyName) && ts.isIdentifier(el.name)) facts.renamed.set(el.name.text, el.propertyName.text);
    } else if (ts.isImportDeclaration(node) && external(node.moduleSpecifier) && node.importClause?.namedBindings && ts.isNamedImports(node.importClause.namedBindings)) {
      for (const el of node.importClause.namedBindings.elements) if (el.propertyName) facts.renamed.set(el.name.text, el.propertyName.text);
    } else if (ts.isParameter(node) && ts.isIdentifier(node.name)) {
      const cls = typeName(node.type);
      if (cls) {
        facts.instances.set(node.name.text, cls);
        // constructor(private readonly users: UserService) declares the field this.users.
        if (ts.isConstructorDeclaration(node.parent) && ts.getModifiers(node)?.length) facts.fields.set(`${classContext(node.parent) ?? ""}#${node.name.text}`, cls);
      }
    } else if (ts.isPropertyDeclaration(node) && ts.isIdentifier(node.name)) {
      const cls = constructed(node.initializer) ?? typeName(node.type);
      if (cls) facts.fields.set(`${classContext(node) ?? ""}#${node.name.text}`, cls);
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(node.left) && node.left.expression.kind === ts.SyntaxKind.ThisKeyword) {
      // this.repo = new Repo()  /  this.repo = repo (a parameter declared as Repo)
      const cls = constructed(node.right) ?? (ts.isIdentifier(node.right) ? facts.instances.get(node.right.text) : null);
      if (cls) facts.fields.set(`${classContext(node) ?? ""}#${node.left.name.text}`, cls);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return facts;
}

/** Calls that never return: the code after them only runs when they weren't reached. */
const NEVER_RETURNS = /^(?:process\.exit|notFound|redirect|permanentRedirect|assert\.fail)$/;

/** How a statement leaves the code after it (see `ExitKind`). */
function exitKind(stmt: ts.Statement | undefined): ExitKind {
  if (!stmt) return "none";
  if (ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt)) return "leave";
  if (ts.isBreakStatement(stmt)) return "break";
  if (ts.isContinueStatement(stmt)) return "continue";
  if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression) && NEVER_RETURNS.test(stmt.expression.expression.getText().replace(/\s+/g, ""))) return "leave";
  if (ts.isBlock(stmt)) {
    for (const s of stmt.statements) {
      const kind = exitKind(s);
      if (kind !== "none") return kind;
    }
    return "none";
  }
  if (ts.isIfStatement(stmt)) {
    const a = exitKind(stmt.thenStatement);
    const b = exitKind(stmt.elseStatement);
    if (a === "none" || b === "none") return "none";
    // Both branches leave; if either only leaves the loop, that is the weaker guarantee.
    return a === "leave" ? b : a;
  }
  if (ts.isTryStatement(stmt)) {
    const fin = exitKind(stmt.finallyBlock);
    if (fin !== "none") return fin;
    const body = exitKind(stmt.tryBlock);
    const handler = stmt.catchClause ? exitKind(stmt.catchClause.block) : body;
    if (body === "none" || handler === "none") return "none";
    return body === "leave" ? handler : body;
  }
  return "none";
}

function hasDirective(statements: ts.NodeArray<ts.Statement>, directive: string): boolean {
  for (const stmt of statements) {
    if (!ts.isExpressionStatement(stmt) || !ts.isStringLiteral(stmt.expression)) return false;
    if (stmt.expression.text === directive) return true;
  }
  return false;
}

/** A property name that is known statically: `a`, `"a"`, `1`; null for computed keys. */
function propertyKey(name: ts.Node): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name) || ts.isPrivateIdentifier(name)) return name.text;
  return null;
}

/** The static key of `obj.key` / `obj["key"]`, or null for `obj[expr]`. */
function accessKey(node: ts.Node): string | null {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node)) return propertyKey(node.argumentExpression);
  return null;
}

function intersect(a: ReadonlySet<string> | undefined, b: ReadonlySet<string> | undefined): ReadonlySet<string> | undefined {
  if (!a || !b) return undefined;
  if (a === b) return a;
  const out = new Set([...a].filter((x) => b.has(x)));
  return out.size ? out : undefined;
}

const SINK_CONTEXT: Record<string, string> = {
  "AEG-TAINT-XSS": "HTML",
  "AEG-TAINT-SQL": "SQL",
  "AEG-TAINT-CMD": "shell",
  "AEG-TAINT-PATH": "file paths",
  "AEG-TAINT-SSRF": "URLs",
  "AEG-TAINT-REDIRECT": "redirects",
  "AEG-TAINT-SSTI": "templates",
  "AEG-TAINT-REDOS": "regular expressions",
};

/**
 * A regex literal only validates a whole value when every top-level alternative
 * is anchored at both ends (`/^\d+$/`, not `/^\d+|x/`) and it doesn't simply
 * accept anything (`/^.*$/`).
 */
export function isStrictPattern(literal: string): boolean {
  const body = literal.slice(1, literal.lastIndexOf("/"));
  if (/(?<!\\)(?:\\\\)*\.[*+]|\[\\s\\S\][*+]|\[\\w\\W\][*+]|\[\\d\\D\][*+]|\[\^\][*+]/.test(body)) return false;
  const alternatives: string[] = [];
  let depth = 0;
  let inClass = false;
  let current = "";
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === "\\") {
      current += ch + (body[++i] ?? "");
      continue;
    }
    if (inClass) inClass = ch !== "]";
    else if (ch === "[") inClass = true;
    else if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "|" && depth === 0) {
      alternatives.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  alternatives.push(current);
  return alternatives.every((alt) => alt.startsWith("^") && /(?<!\\)(?:\\\\)*\$$/.test(alt));
}

/** Maps export names to the local function names that implement them (ESM and CommonJS). */
export function exportedFunctionNames(sf: ts.SourceFile): Map<string, string> {
  const out = new Map<string, string>();
  const hasMod = (n: ts.Node, kind: ts.SyntaxKind) => ts.canHaveModifiers(n) && !!ts.getModifiers(n)?.some((m) => m.kind === kind);
  for (const stmt of sf.statements) {
    if ((ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt)) && stmt.name && hasMod(stmt, ts.SyntaxKind.ExportKeyword)) {
      out.set(hasMod(stmt, ts.SyntaxKind.DefaultKeyword) ? "default" : stmt.name.text, stmt.name.text);
      if (hasMod(stmt, ts.SyntaxKind.DefaultKeyword)) out.set(stmt.name.text, stmt.name.text);
    } else if (ts.isVariableStatement(stmt) && hasMod(stmt, ts.SyntaxKind.ExportKeyword)) {
      for (const d of stmt.declarationList.declarations) if (ts.isIdentifier(d.name)) out.set(d.name.text, d.name.text);
    } else if (ts.isExportDeclaration(stmt) && !stmt.moduleSpecifier && stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
      for (const el of stmt.exportClause.elements) out.set(el.name.text, (el.propertyName ?? el.name).text);
    } else if (ts.isExportAssignment(stmt) && ts.isIdentifier(stmt.expression)) {
      out.set("default", stmt.expression.text);
    } else if (ts.isExpressionStatement(stmt) && ts.isBinaryExpression(stmt.expression) && stmt.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = stmt.expression.left.getText(sf).replace(/\s+/g, "");
      const right = stmt.expression.right;
      if (left === "module.exports") {
        if (ts.isIdentifier(right)) out.set("default", right.text);
        else if (ts.isObjectLiteralExpression(right)) {
          for (const p of right.properties) {
            if (ts.isShorthandPropertyAssignment(p)) out.set(p.name.text, p.name.text);
            else if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.initializer)) out.set(p.name.getText(sf), p.initializer.text);
          }
        }
      } else {
        const m = /^(?:module\.)?exports\.([\w$]+)$/.exec(left);
        if (m) out.set(m[1], ts.isIdentifier(right) ? right.text : `exports.${m[1]}`);
      }
    }
  }
  return out;
}

export function analyzeTaint(sf: ts.SourceFile, file: string, imports?: ImportMap): Finding[] {
  return new TaintAnalyzer(sf, file, imports).run();
}
