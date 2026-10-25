import type { Finding, Language, Severity, TraceStep } from "../types";
import type { SourceViews } from "../lexer";
import { makeFinding } from "../finding";
import { SINKS, type SinkSpec } from "./model";

/**
 * Line-oriented taint tracking for languages without a bundled parser
 * (Python, PHP). Less precise than the AST engine, but it follows values
 * through assignments, string formatting and reassignment, and it knows which
 * call argument is dangerous (so `execute(sql, params)` with tainted params is safe).
 */

interface LexSink {
  sink: string;
  /** Regex matched at the start of a call; the call's argument list starts right after the match. */
  call: RegExp;
  arg: number | "any";
  /** Extra condition on the full argument text. */
  when?: (args: string) => boolean;
  severity?: Severity;
  title?: string;
}

interface LexConfig {
  sources: Array<{ re: RegExp; label: string }>;
  assign: RegExp;
  sanitizers: RegExp;
  sinks: LexSink[];
  /** Normalises a variable reference (strip `$`). */
  varRef: (name: string) => RegExp;
}

const PY: LexConfig = {
  sources: [
    { re: /\brequest\.(?:args|form|values|json|data|cookies|headers|files|GET|POST|body|query_params|path_params|get_json\s*\(|get_data\s*\()/, label: "HTTP request input" },
    { re: /\bsys\.argv\b/, label: "command-line argument" },
    { re: /(?<![\w.])input\s*\(/, label: "user input()" },
    { re: /\bself\.request\.(?:arguments|body|query)\b|\bself\.get_argument\s*\(/, label: "HTTP request input" },
  ],
  assign: /^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[\w[\], .|]+)?\s*(\+?=)(?!=)\s*(.+)$/,
  sanitizers: /\b(?:int|float|bool|len|abs|uuid\.UUID|shlex\.quote|html\.escape|escape|bleach\.clean|secure_filename|os\.path\.basename|markupsafe\.escape|quote_plus|quote|ipaddress\.ip_address)\s*\(/,
  varRef: (n) => new RegExp(`(?<![\\w.'"])${n}\\b(?!\\s*=[^=])`),
  sinks: [
    { sink: "AEG-TAINT-SQL", call: /\.(?:execute|executemany|executescript|raw|text)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-CMD", call: /\bos\.(?:system|popen[23]?)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-CMD", call: /\bsubprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(/, arg: 0, when: (a) => /shell\s*=\s*True/.test(a) || /getoutput|getstatus/.test(a) },
    { sink: "AEG-TAINT-CMD", call: /\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(/, arg: 0, severity: "medium", title: "Argument injection into subprocess" },
    { sink: "AEG-TAINT-CODE", call: /(?<![\w.])(?:eval|exec)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-PATH", call: /(?<![\w.])open\s*\(|\b(?:send_file|os\.remove|os\.unlink|shutil\.(?:rmtree|copy|copyfile|move)|os\.listdir|Path)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-SSRF", call: /\b(?:requests|httpx|session|client)\.(?:get|post|put|patch|delete|head|request)\s*\(|\burllib\.request\.urlopen\s*\(|\burlopen\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-REDIRECT", call: /(?<![\w.])redirect\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-SSTI", call: /\b(?:render_template_string|Template|jinja2\.Template|Environment\(\)\.from_string)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-DESER", call: /\b(?:pickle|cPickle|marshal|dill)\.loads?\s*\(|\byaml\.(?:load|unsafe_load)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-XSS", call: /\b(?:Markup|mark_safe|make_response|HttpResponse)\s*\(/, arg: 0, when: (a) => /<\/?[a-z]/i.test(a) || !/['"]/.test(a) },
  ],
};

const PHP: LexConfig = {
  sources: [
    { re: /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/, label: "HTTP request input" },
    { re: /\$_SERVER\s*\[\s*['"](?:HTTP_\w+|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO)['"]/, label: "HTTP header / URL" },
    { re: /file_get_contents\s*\(\s*['"]php:\/\/input['"]/, label: "raw request body" },
  ],
  assign: /^\s*\$(\w+)\s*(\.?=)(?!=)\s*(.+?);?\s*$/,
  sanitizers: /\b(?:intval|floatval|boolval|htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd|mysqli_real_escape_string|real_escape_string|addslashes|basename|filter_var|filter_input|strip_tags|urlencode|rawurlencode|password_hash|hash)\s*\(|\(int\)|\(float\)|\(bool\)/,
  varRef: (n) => new RegExp(`\\$${n}\\b`),
  sinks: [
    { sink: "AEG-TAINT-SQL", call: /\b(?:mysql_query|pg_query|sqlite_query)\s*\(|->(?:query|exec|multi_query)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-SQL", call: /\bmysqli_(?:query|multi_query)\s*\(/, arg: 1 },
    { sink: "AEG-TAINT-CMD", call: /\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-CODE", call: /\b(?:eval|assert|create_function)\s*\(/, arg: "any" },
    { sink: "AEG-TAINT-PATH", call: /\b(?:include|require)(?:_once)?\b\s*\(?|\b(?:fopen|readfile|file|unlink|file_put_contents|move_uploaded_file)\s*\(/, arg: 0, title: "File inclusion / path traversal" },
    { sink: "AEG-TAINT-SSRF", call: /\b(?:file_get_contents|curl_init|fsockopen|get_headers)\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-REDIRECT", call: /\bheader\s*\(/, arg: 0, when: (a) => /Location\s*:/i.test(a) },
    { sink: "AEG-TAINT-DESER", call: /\bunserialize\s*\(/, arg: 0 },
    { sink: "AEG-TAINT-XSS", call: /\b(?:echo|print)\b/, arg: "any" },
  ],
};

/**
 * Splits an expression into the operands joined at the top level by string
 * concatenation / formatting (`.` in PHP, `+` and `%` in Python, `,` in both).
 */
export function operands(expr: string, lang: Language): string[] {
  const seps = lang === "php" ? ".," : "+%,";
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let cur = "";
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i];
    if (quote) {
      cur += c;
      if (c === "\\") cur += expr[++i] ?? "";
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if ("([{".includes(c)) depth++;
    if (")]}".includes(c)) depth--;
    // A PHP "." between digits is a decimal point, not concatenation.
    const decimal = c === "." && /\d/.test(expr[i - 1] ?? "") && /\d/.test(expr[i + 1] ?? "");
    if (depth === 0 && seps.includes(c) && !decimal && !(c === "." && expr[i + 1] === "=")) {
      if (cur.trim()) out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** True when `op` is entirely one sanitiser call (`intval(...)`, `html.escape(...)`) or a PHP numeric cast. */
function wrappedBy(op: string, sanitizers: RegExp): boolean {
  const m = new RegExp(`^(?:${sanitizers.source})`).exec(op);
  if (!m) return false;
  if (/^\((?:int|float|bool)\)/.test(m[0])) return true;
  // The sanitiser's opening paren must close at the very end of the operand.
  let depth = 0;
  for (let i = m[0].length - 1; i < op.length; i++) {
    if (op[i] === "(") depth++;
    else if (op[i] === ")" && --depth === 0) return i === op.trimEnd().length - 1;
  }
  return false;
}

/** Returns the text of each top-level argument starting at `open` (index just past '('). */
function splitArgs(text: string, open: number): { args: string[]; full: string } {
  const args: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = "";
  let i = open;
  for (; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      current += c;
      if (c === "\\") current += text[++i] ?? "";
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      current += c;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth++;
    if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) break;
      depth--;
    }
    if (c === "," && depth === 0) {
      args.push(current.trim());
      current = "";
      continue;
    }
    if (c === ";" && depth === 0) break;
    current += c;
  }
  if (current.trim()) args.push(current.trim());
  return { args, full: text.slice(open, i) };
}

export function lexicalTaint(views: SourceViews, lang: Language, file: string): Finding[] {
  const cfg = lang === "python" ? PY : lang === "php" ? PHP : null;
  if (!cfg) return [];

  const lines = views.noComments.split("\n");
  const tainted = new Map<string, TraceStep[]>();
  const findings: Finding[] = [];
  const seen = new Set<string>();

  const rawTaint = (expr: string): TraceStep[] | null => {
    for (const src of cfg.sources) if (src.re.test(expr)) return [];
    for (const [name, trace] of tainted) if (cfg.varRef(name).test(expr)) return trace;
    return null;
  };

  // An expression is tainted if any concatenated operand is, unless that operand is wrapped whole in a sanitiser.
  const taintOf = (expr: string): TraceStep[] | null => {
    for (const op of operands(expr, lang)) {
      if (wrappedBy(op, cfg.sanitizers)) continue;
      const t = rawTaint(op);
      if (t !== null) return t;
    }
    return null;
  };

  const sourceLabel = (expr: string) => cfg.sources.find((s) => s.re.test(expr))?.label ?? "untrusted input";

  lines.forEach((line, i) => {
    const lineNo = i + 1;
    if (!line.trim()) return;

    // 1. Sinks on this line.
    for (const ls of cfg.sinks) {
      const re = new RegExp(ls.call.source, "g");
      for (const m of line.matchAll(re)) {
        const { args, full } = splitArgs(line, m.index! + m[0].length);
        if (ls.when && !ls.when(full)) continue;
        const candidates = ls.arg === "any" ? args : args[ls.arg] !== undefined ? [args[ls.arg]] : [];
        for (const arg of candidates) {
          const trace = taintOf(arg);
          if (trace === null) continue;
          const spec = SINKS.find((s) => s.id === ls.sink) as SinkSpec;
          const key = `${spec.id}:${lineNo}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const sourceStep: TraceStep[] = trace.length ? trace : [{ kind: "source", line: lineNo, label: sourceLabel(arg), snippet: arg.slice(0, 90) }];
          const steps: TraceStep[] = [...sourceStep, { kind: "sink", line: lineNo, label: `reaches ${spec.title.toLowerCase()} sink`, snippet: line.trim().slice(0, 90) }];
          const col = m.index! + 1;
          findings.push(
            makeFinding({
              rule: spec,
              file,
              location: { line: lineNo, column: col, endLine: lineNo, endColumn: col + m[0].length + full.length },
              snippet: line,
              confidence: spec.confidence * (trace.length > 4 ? 0.8 : 0.9) * (ls.severity ? 0.8 : 1),
              detector: "taint",
              trace: steps,
              severity: ls.severity,
              title: `${ls.title ?? spec.title}: ${steps[0].label} → line ${lineNo}`,
            })
          );
        }
      }
    }

    // 2. Reflected XSS in Python view functions: return f"<h1>{name}</h1>".
    if (lang === "python") {
      const ret = /^\s*return\s+(f['"].*<\/?[a-z][^'"]*['"].*)$/i.exec(line);
      if (ret) {
        const trace = taintOf(ret[1]);
        const key = `xss:${lineNo}`;
        if (trace !== null && !seen.has(key)) {
          seen.add(key);
          const spec = SINKS.find((s) => s.id === "AEG-TAINT-XSS")!;
          const steps: TraceStep[] = [...(trace.length ? trace : [{ kind: "source" as const, line: lineNo, label: sourceLabel(ret[1]), snippet: ret[1].slice(0, 90) }]), { kind: "sink", line: lineNo, label: "returned as HTML response", snippet: line.trim().slice(0, 90) }];
          findings.push(makeFinding({ rule: spec, file, location: { line: lineNo, column: 1, endLine: lineNo, endColumn: line.length + 1 }, snippet: line, confidence: 0.75, detector: "taint", trace: steps, title: `Reflected cross-site scripting: ${steps[0].label} → line ${lineNo}` }));
        }
      }
    }

    // 3. Assignments update the taint map (reassignment with clean data clears it).
    const am = cfg.assign.exec(line);
    if (am) {
      const names = am[1].split(",").map((n) => n.trim());
      const append = am[2] !== "=";
      const trace = taintOf(am[3]);
      for (const name of names) {
        if (trace !== null) {
          const prior = trace.length ? trace : [{ kind: "source" as const, line: lineNo, label: sourceLabel(am[3]), snippet: am[3].trim().slice(0, 90) }];
          tainted.set(name, [...prior, { kind: "propagation" as const, line: lineNo, label: `assigned to \`${name}\``, snippet: line.trim().slice(0, 90) }].slice(-8));
        } else if (!append) {
          tainted.delete(name);
        }
      }
    }

    // 4. Python for-loops over tainted iterables taint the loop variable.
    if (lang === "python") {
      const loop = /^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.+):\s*$/.exec(line);
      if (loop) {
        const trace = taintOf(loop[2]);
        if (trace !== null) tainted.set(loop[1], [...trace, { kind: "propagation", line: lineNo, label: `loop variable \`${loop[1]}\``, snippet: line.trim() }]);
      }
    }
  });

  return findings;
}
