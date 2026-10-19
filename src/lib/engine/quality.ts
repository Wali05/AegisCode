import ts from "typescript";
import type { FileMetrics, Finding, RuleMeta } from "./types";
import { makeFinding } from "./finding";
import { functionName } from "./metrics";
import { OWASP } from "./rules/patterns";

type QualityRule = Pick<RuleMeta, "id" | "title" | "severity" | "category" | "cwe" | "owasp" | "description" | "remediation">;

export const QUALITY_RULES: Record<string, QualityRule> = {
  quadratic: {
    id: "AEG-PERF-001",
    title: "Linear search inside a loop (O(n²))",
    severity: "low",
    category: "performance",
    cwe: ["CWE-407"],
    description: "A linear scan (.includes/.indexOf/.find/.filter) runs on every iteration, turning the loop quadratic. On large inputs this is a latency cliff and a cheap DoS vector.",
    remediation: "Build a Set or Map once before the loop and use O(1) .has()/.get() lookups.",
  },
  awaitInLoop: {
    id: "AEG-PERF-002",
    title: "Sequential await inside a loop",
    severity: "low",
    category: "performance",
    cwe: ["CWE-1050"],
    description: "Each iteration waits for the previous one; independent I/O is serialised and total latency grows linearly.",
    remediation: "Collect the promises and await Promise.all() (with a concurrency limit such as p-limit for large batches).",
  },
  syncInHandler: {
    id: "AEG-PERF-003",
    title: "Blocking synchronous call in a request handler",
    severity: "medium",
    category: "dos",
    cwe: ["CWE-400"],
    owasp: OWASP.design,
    description: "Synchronous filesystem, process or KDF calls block the event loop for every concurrent request.",
    remediation: "Use the async variant (fs.promises, crypto.scrypt with a callback, execFile) or move the work off the request path.",
  },
  jsonClone: {
    id: "AEG-PERF-004",
    title: "Deep clone via JSON round-trip",
    severity: "info",
    category: "performance",
    cwe: ["CWE-1176"],
    description: "JSON.parse(JSON.stringify(x)) is slow and silently drops Dates, Maps, undefined and BigInts.",
    remediation: "Use structuredClone(x).",
  },
  unboundedCache: {
    id: "AEG-MEM-001",
    title: "Unbounded module-level cache (memory leak)",
    severity: "medium",
    category: "dos",
    cwe: ["CWE-401", "CWE-770"],
    owasp: OWASP.design,
    description: "A module-scoped Map/Set/object grows on every call and is never evicted. In a long-lived server process this leaks memory until the process is OOM-killed.",
    remediation: "Bound the cache (LRU with a max size / TTL) or scope it to the request.",
  },
  effectLeak: {
    id: "AEG-MEM-002",
    title: "Effect subscribes without cleanup",
    severity: "low",
    category: "code-quality",
    cwe: ["CWE-401"],
    description: "A React effect registers a listener, interval or subscription but returns no cleanup function, so handlers accumulate on every re-render or remount.",
    remediation: "Return a cleanup function from the effect that removes the listener / clears the timer.",
  },
  complexity: {
    id: "AEG-QUAL-001",
    title: "Function exceeds complexity budget",
    severity: "low",
    category: "code-quality",
    cwe: ["CWE-1121"],
    description: "High cyclomatic complexity correlates strongly with defect density and makes security review error-prone.",
    remediation: "Extract branches into well-named helpers, replace conditionals with lookup tables, and add tests for each path.",
  },
  nesting: {
    id: "AEG-QUAL-002",
    title: "Deeply nested control flow",
    severity: "low",
    category: "code-quality",
    cwe: ["CWE-1124"],
    description: "Nesting beyond four levels hides edge cases and early-exit bugs.",
    remediation: "Use guard clauses / early returns to flatten the structure.",
  },
};

const LINEAR_METHODS = new Set(["includes", "indexOf", "lastIndexOf", "find", "findIndex", "filter", "some"]);
const ITERATION_METHODS = new Set(["map", "forEach", "filter", "reduce", "flatMap", "some", "every", "find"]);
const SYNC_BLOCKING = /(?:^|\.)(?:readFileSync|writeFileSync|readdirSync|statSync|existsSync|execSync|spawnSync|execFileSync|pbkdf2Sync|scryptSync|randomFillSync|gzipSync|gunzipSync|deflateSync|inflateSync|hashSync|compareSync)$/;
const HANDLER_NAMES = /^(?:GET|POST|PUT|PATCH|DELETE|handler)$/;
const ROUTER = /\.(?:get|post|put|patch|delete|all|use)$/;

export function analyzeQuality(sf: ts.SourceFile, file: string, metrics: FileMetrics): Finding[] {
  const out: Finding[] = [];
  const text = (n: ts.Node) => n.getText(sf).replace(/\s+/g, "");
  const pos = (n: ts.Node) => {
    const s = sf.getLineAndCharacterOfPosition(n.getStart(sf));
    const e = sf.getLineAndCharacterOfPosition(n.getEnd());
    return { line: s.line + 1, column: s.character + 1, endLine: e.line + 1, endColumn: e.character + 1 };
  };
  const lineText = (line: number) => sf.text.split("\n")[line - 1] ?? "";
  const push = (rule: QualityRule, node: ts.Node, confidence: number, extra?: Partial<{ title: string; description: string }>) => {
    const location = pos(node);
    out.push(makeFinding({ rule, file, location, snippet: lineText(location.line), confidence, detector: "metric", ...extra }));
  };

  const loopDepthStack: number[] = [0];
  const loopLocals: Array<Set<string>> = [];
  const handlerStack: boolean[] = [false];
  const reportedAwaitLoops = new Set<ts.Node>();

  const isLoop = (n: ts.Node) => ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isWhileStatement(n) || ts.isDoStatement(n);

  const isIterationCallback = (n: ts.Node) =>
    (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) &&
    n.parent &&
    ts.isCallExpression(n.parent) &&
    ts.isPropertyAccessExpression(n.parent.expression) &&
    ITERATION_METHODS.has(n.parent.expression.name.text);

  const visit = (n: ts.Node, enclosingLoop: ts.Node | null) => {
    const loopDepth = loopDepthStack[loopDepthStack.length - 1];
    let pushedLoop = false;
    let pushedFn = false;

    if (ts.isFunctionLike(n) && !isIterationCallback(n)) {
      const name = ts.isFunctionDeclaration(n) && n.name ? n.name.text : "";
      const isHandler = HANDLER_NAMES.test(name) || (!!n.parent && ts.isCallExpression(n.parent) && ROUTER.test(text(n.parent.expression)));
      handlerStack.push(isHandler || handlerStack[handlerStack.length - 1]);
      loopDepthStack.push(0); // a new function resets loop context
      pushedFn = true;
    } else if (isLoop(n) || isIterationCallback(n)) {
      loopDepthStack.push(loopDepth + 1);
      const locals = new Set<string>();
      n.forEachChild(function collect(c: ts.Node) {
        if (ts.isVariableDeclaration(c) && ts.isIdentifier(c.name)) locals.add(c.name.text);
        c.forEachChild(collect);
      });
      loopLocals.push(locals);
      pushedLoop = true;
    }

    const inLoop = loopDepthStack[loopDepthStack.length - 1] > 0;

    if (ts.isCallExpression(n)) {
      const callee = text(n.expression);

      if (inLoop && ts.isPropertyAccessExpression(n.expression) && LINEAR_METHODS.has(n.expression.name.text)) {
        const recv = n.expression.expression;
        const recvName = ts.isIdentifier(recv) ? recv.text : ts.isPropertyAccessExpression(recv) ? recv.getText(sf) : null;
        const isStringOp = n.expression.name.text === "includes" && n.arguments[0] && ts.isStringLiteralLike(n.arguments[0]);
        const local = recvName && loopLocals.some((s) => s.has(recvName.split(".")[0]));
        if (recvName && !local && !isStringOp && !/^(?:Object|Array|String)\b/.test(recvName)) {
          push(QUALITY_RULES.quadratic, n, 0.55, { description: `\`${recvName}.${n.expression.name.text}()\` scans the whole collection on every iteration. ${QUALITY_RULES.quadratic.description}` });
        }
      }

      if (handlerStack[handlerStack.length - 1] && SYNC_BLOCKING.test(callee)) push(QUALITY_RULES.syncInHandler, n, 0.65);

      if (/^JSON\.parse$/.test(callee) && n.arguments[0] && ts.isCallExpression(n.arguments[0]) && /^JSON\.stringify$/.test(text(n.arguments[0].expression))) {
        push(QUALITY_RULES.jsonClone, n, 0.9);
      }

      if (/^(?:React\.)?(?:useEffect|useLayoutEffect)$/.test(callee) && n.arguments[0] && (ts.isArrowFunction(n.arguments[0]) || ts.isFunctionExpression(n.arguments[0]))) {
        const body = n.arguments[0].body;
        const bodyText = body.getText(sf);
        const subscribes = /\b(?:addEventListener|setInterval|subscribe|\.on\()\s*\(?/.test(bodyText);
        const hasCleanup = ts.isBlock(body) && body.statements.some((s) => ts.isReturnStatement(s) && !!s.expression);
        if (subscribes && !hasCleanup) push(QUALITY_RULES.effectLeak, n, 0.7);
      }
    }

    if (ts.isAwaitExpression(n) && inLoop && enclosingLoop && !reportedAwaitLoops.has(enclosingLoop)) {
      const isForAwait = ts.isForOfStatement(enclosingLoop) && !!enclosingLoop.awaitModifier;
      const isCallbackLoop = isIterationCallback(enclosingLoop);
      if (!isForAwait && !isCallbackLoop) {
        reportedAwaitLoops.add(enclosingLoop);
        push(QUALITY_RULES.awaitInLoop, n, 0.5);
      }
    }

    const nextLoop = isLoop(n) || isIterationCallback(n) ? n : ts.isFunctionLike(n) ? null : enclosingLoop;
    n.forEachChild((c) => visit(c, nextLoop));

    if (pushedLoop) {
      loopDepthStack.pop();
      loopLocals.pop();
    }
    if (pushedFn) {
      loopDepthStack.pop();
      handlerStack.pop();
    }
  };
  visit(sf, null);

  // Module-level caches that only ever grow.
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) continue;
    for (const decl of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(decl.name) || !decl.initializer) continue;
      const init = decl.initializer;
      const isCollection = (ts.isNewExpression(init) && /^(?:Map|Set)$/.test(init.expression.getText(sf))) || (ts.isObjectLiteralExpression(init) && init.properties.length === 0) || (ts.isArrayLiteralExpression(init) && init.elements.length === 0);
      if (!isCollection) continue;
      const name = decl.name.text.replace(/[$]/g, "\\$");
      // Search everything except the declaration itself.
      const body = sf.text.slice(0, stmt.getStart(sf)) + sf.text.slice(stmt.getEnd());
      const grows = new RegExp(`\\b${name}\\s*(?:\\.(?:set|add|push)\\s*\\(|\\[[^\\]]+\\]\\s*=)`).test(body);
      const shrinks = new RegExp(`\\b${name}\\s*\\.(?:delete|clear|shift|pop|splice)\\s*\\(|\\b${name}\\s*=\\s*(?:new|\\[|\\{)|\\bdelete\\s+${name}\\[|\\b${name}\\.length\\s*=|\\b${name}\\.size\\s*[>]=?`).test(body);
      const growsInFunction = grows && /function|=>/.test(body);
      if (growsInFunction && !shrinks && /cache|memo|store|seen|registry|map|sessions|clients|listeners|queue|buffer|history|log/i.test(decl.name.text)) {
        push(QUALITY_RULES.unboundedCache, decl, 0.6, { description: `\`${decl.name.text}\` is written to but never evicted. ${QUALITY_RULES.unboundedCache.description}` });
      }
    }
  }

  // Complexity budget per function.
  const fnNodes = new Map<number, ts.Node>();
  const collect = (n: ts.Node) => {
    if (ts.isFunctionLike(n)) fnNodes.set(sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1, n);
    n.forEachChild(collect);
  };
  collect(sf);
  for (const fn of metrics.functions) {
    const node = fnNodes.get(fn.line);
    if (!node) continue;
    const name = ts.isFunctionLike(node) && "body" in node ? functionName(node as ts.FunctionLikeDeclaration, sf) : fn.name;
    if (fn.complexity > 15) {
      push({ ...QUALITY_RULES.complexity, severity: fn.complexity > 30 ? "medium" : "low" }, node, 0.9, {
        title: `\`${name}\` has cyclomatic complexity ${fn.complexity}`,
        description: `${QUALITY_RULES.complexity.description} Budget is 15; this function has ${fn.complexity} independent paths across ${fn.loc} lines.`,
      });
    }
    if (fn.maxNesting > 4) {
      push(QUALITY_RULES.nesting, node, 0.85, { title: `\`${name}\` nests ${fn.maxNesting} levels deep` });
    }
  }

  return out;
}

/** Complexity findings for languages without an AST (driven by lexical metrics). */
export function lexicalQuality(file: string, metrics: FileMetrics, lineText: (line: number) => string): Finding[] {
  const out: Finding[] = [];
  for (const fn of metrics.functions) {
    const location = { line: fn.line, column: 1, endLine: fn.endLine, endColumn: 1 };
    if (fn.complexity > 15) {
      out.push(
        makeFinding({
          rule: { ...QUALITY_RULES.complexity, severity: fn.complexity > 30 ? "medium" : "low" },
          file,
          location,
          snippet: lineText(fn.line),
          confidence: 0.75,
          detector: "metric",
          title: `\`${fn.name}\` has cyclomatic complexity ≈${fn.complexity}`,
        })
      );
    }
    if (fn.maxNesting > 4) {
      out.push(makeFinding({ rule: QUALITY_RULES.nesting, file, location, snippet: lineText(fn.line), confidence: 0.7, detector: "metric", title: `\`${fn.name}\` nests ${fn.maxNesting} levels deep` }));
    }
  }
  return out;
}
