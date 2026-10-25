import ts from "typescript";
import { TaintAnalyzer, parseSource, type ExportedSummary, type ImportMap } from "./analyzer";

/**
 * Cross-file taint analysis.
 *
 * Every JS/TS module is summarised in isolation (which parameters of each
 * exported function reach a sink, which flow to the return value). Importers
 * then see those summaries through their `import` / `require` bindings, so a
 * route in `routes/orders.ts` that passes `req.query.id` to `findOrders()` in
 * `db/orders.ts` is reported at the real sink with the full two-file trace.
 * Summaries are recomputed for a few rounds so chains like a → b → c resolve.
 */

interface ImportSpec {
  local: string;
  spec: string;
  /** Export name, `default`, or `*` for namespace / CommonJS module objects. */
  imported: string;
}

const EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];
const ROUNDS = 3;

export function collectImports(sf: ts.SourceFile): ImportSpec[] {
  const out: ImportSpec[] = [];
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier) && stmt.importClause && !stmt.importClause.isTypeOnly) {
      const spec = stmt.moduleSpecifier.text;
      const clause = stmt.importClause;
      if (clause.name) out.push({ local: clause.name.text, spec, imported: "default" });
      const nb = clause.namedBindings;
      if (nb && ts.isNamespaceImport(nb)) out.push({ local: nb.name.text, spec, imported: "*" });
      if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) if (!el.isTypeOnly) out.push({ local: el.name.text, spec, imported: (el.propertyName ?? el.name).text });
      }
    }
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        const init = d.initializer;
        if (!init || !ts.isCallExpression(init) || !ts.isIdentifier(init.expression) || init.expression.text !== "require") continue;
        const arg = init.arguments[0];
        if (!arg || !ts.isStringLiteral(arg)) continue;
        if (ts.isIdentifier(d.name)) out.push({ local: d.name.text, spec: arg.text, imported: "*" });
        else if (ts.isObjectBindingPattern(d.name)) {
          for (const el of d.name.elements) {
            if (!ts.isIdentifier(el.name)) continue;
            const key = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
            out.push({ local: el.name.text, spec: arg.text, imported: key });
          }
        }
      }
    }
  }
  return out;
}

function collectReexports(sf: ts.SourceFile): Array<{ spec: string; names: Map<string, string> | null }> {
  const out: Array<{ spec: string; names: Map<string, string> | null }> = [];
  for (const stmt of sf.statements) {
    if (!ts.isExportDeclaration(stmt) || !stmt.moduleSpecifier || !ts.isStringLiteral(stmt.moduleSpecifier) || stmt.isTypeOnly) continue;
    const clause = stmt.exportClause;
    if (!clause) out.push({ spec: stmt.moduleSpecifier.text, names: null });
    else if (ts.isNamedExports(clause)) {
      out.push({ spec: stmt.moduleSpecifier.text, names: new Map(clause.elements.map((el) => [el.name.text, (el.propertyName ?? el.name).text])) });
    }
  }
  return out;
}

function normalize(path: string): string {
  const parts: string[] = [];
  for (const seg of path.split("/")) {
    if (!seg || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return parts.join("/");
}

export class ProjectIndex {
  private files = new Map<string, ts.SourceFile>();
  private imports = new Map<string, ImportSpec[]>();
  private exports = new Map<string, Map<string, ExportedSummary>>();
  /** `export * from "./x"` and `export { a as b } from "./x"` per file (null names = everything). */
  private reexports = new Map<string, Array<{ spec: string; names: Map<string, string> | null }>>();

  constructor(files: Array<{ path: string; code: string }>) {
    for (const f of files) {
      if (!/\.(?:[cm]?[jt]sx?)$/i.test(f.path)) continue;
      const sf = parseSource(f.path, f.code);
      this.files.set(f.path, sf);
      this.imports.set(f.path, collectImports(sf));
      this.reexports.set(f.path, collectReexports(sf));
    }
    for (let round = 0; round < ROUNDS; round++) {
      for (const [path, sf] of this.files) {
        const own = new TaintAnalyzer(sf, path, this.importsFor(path)).exportSummaries();
        for (const re of this.reexports.get(path) ?? []) {
          const target = this.resolve(path, re.spec);
          const theirs = target ? this.exports.get(target) : undefined;
          if (!theirs) continue;
          if (!re.names) {
            for (const [k, v] of theirs) if (k !== "default" && !own.has(k)) own.set(k, v);
          } else {
            for (const [exported, imported] of re.names) if (theirs.has(imported)) own.set(exported, theirs.get(imported)!);
          }
        }
        this.exports.set(path, own);
      }
    }
  }

  get size(): number {
    return this.files.size;
  }

  /** Resolves a module specifier from `from` to a project file, or null for packages / unknown files. */
  resolve(from: string, spec: string): string | null {
    let base: string;
    if (spec.startsWith("./") || spec.startsWith("../")) base = normalize(`${from.split("/").slice(0, -1).join("/")}/${spec}`);
    else if (spec.startsWith("@/") || spec.startsWith("~/")) base = spec.slice(2);
    else return null;

    const stripped = base.replace(/\.(?:[cm]?js|jsx)$/, "");
    const candidates = [base, ...EXTENSIONS.map((e) => stripped + e), ...EXTENSIONS.map((e) => `${base}/index${e}`)];
    // `@/x` usually points at src/x
    if (spec.startsWith("@/") || spec.startsWith("~/")) candidates.push(...candidates.map((c) => `src/${c}`));
    for (const c of candidates) if (this.files.has(c)) return c;
    // Repositories audited from a sub-folder: match on path suffix.
    for (const c of candidates) for (const known of this.files.keys()) if (known.endsWith(`/${c}`)) return known;
    return null;
  }

  importsFor(path: string): ImportMap {
    const map: ImportMap = new Map();
    for (const imp of this.imports.get(path) ?? []) {
      const target = this.resolve(path, imp.spec);
      if (!target) continue;
      const exported = this.exports.get(target);
      if (!exported) continue;
      if (imp.imported === "*") map.set(imp.local, { kind: "ns", members: exported });
      else {
        const summary = exported.get(imp.imported);
        if (summary) map.set(imp.local, { kind: "fn", summary });
      }
    }
    return map;
  }
}
