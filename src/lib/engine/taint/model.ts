import type { FindingCategory, Severity } from "../types";
import { OWASP } from "../rules/patterns";

/**
 * The taint model: where untrusted data enters (sources), which calls neutralise it
 * (sanitisers) and which operations are dangerous when they receive it (sinks).
 */

/** Member-expression chains that yield attacker-controlled data. */
export const SOURCE_MEMBERS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /^(?:req|request|ctx(?:\.request)?|c\.req)\.(?:query|body|params|headers|cookies|signedCookies|url|originalUrl|path|hostname|files?|search|rawBody)\b/, label: "HTTP request input" },
  { pattern: /^(?:req|request)\.nextUrl\b/, label: "HTTP request URL" },
  { pattern: /^(?:event|evt)\.(?:body|queryStringParameters|pathParameters|multiValueQueryStringParameters|headers)\b/, label: "Lambda event input" },
  { pattern: /^(?:window\.)?location\.(?:search|hash|href|pathname)\b|^document\.(?:URL|documentURI|referrer|baseURI)\b|^window\.name\b/, label: "browser URL / DOM input" },
  { pattern: /^(?:e|ev|evt|event|msg|message)\.data\b/, label: "postMessage payload" },
  { pattern: /^process\.argv\b/, label: "command-line argument" },
  { pattern: /^(?:socket|ws)\.handshake\.(?:query|headers|auth)\b/, label: "WebSocket handshake input" },
];

/** Call expressions whose *result* is attacker-controlled. Matched against the callee text. */
export const SOURCE_CALLS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /^(?:req|request)\.(?:json|text|formData|arrayBuffer|blob)$/, label: "HTTP request body" },
  { pattern: /^(?:req|request|c\.req)\.(?:get|header|param|query|cookie)$/, label: "HTTP request input" },
  { pattern: /searchParams\.get(?:All)?$|^(?:useSearchParams|useParams)$/, label: "URL query parameter" },
  { pattern: /^(?:headers|cookies)\(\)\.get$/, label: "request header / cookie" },
  { pattern: /^(?:window\.)?prompt$/, label: "user prompt" },
  { pattern: /^(?:readline|rl)\.question$/, label: "terminal input" },
];

/** Names of destructured handler parameters that carry request data. */
export const REQUEST_BINDINGS = new Set(["query", "body", "params", "headers", "cookies", "searchParams"]);
export const HTTP_HANDLER_NAMES = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|handler|loader|action)$/;
export const ROUTER_CALL = /\.(?:get|post|put|patch|delete|all|use|route|on)$/;

/** Calls whose return value is considered clean regardless of input. */
export const SANITIZER_CALLS: RegExp[] = [
  /^(?:parseInt|parseFloat|Number|Boolean|BigInt|isNaN|isFinite|Array\.isArray)$/,
  /^Math\./,
  /^(?:encodeURIComponent|encodeURI|escape)$/,
  /^(?:DOMPurify|purify|dompurify)\.sanitize$/,
  /^(?:path\.)?basename$/,
  /(?:^|\.)(?:sanitize\w*|escape\w*|encode\w*|validate\w*|is[A-Z]\w*|filterXSS|xss|toNumber|toInt|uuidValidate|hash\w*|createHash|digest|compare\w*)$/i,
  /(?:^|\.)(?:includes|startsWith|endsWith|test|has|indexOf|lastIndexOf|localeCompare|every|some|findIndex)$/,
];

/** Tagged templates that parameterise interpolations (safe SQL builders). */
export const SAFE_TAGS = /^(?:sql|SQL|Prisma\.sql|Prisma\.raw|css|gql|graphql|html)$/;

/** Known string / array methods that pass taint straight through from the receiver. */
export const PASSTHROUGH_METHODS = new Set([
  "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "slice", "substring", "substr", "split",
  "concat", "replace", "replaceAll", "padStart", "padEnd", "toString", "valueOf", "join", "at", "charAt",
  "normalize", "repeat", "flat", "reverse", "sort", "map", "filter", "find", "get", "getAll", "values",
  "entries", "keys", "pop", "shift", "then", "json", "text",
]);

/** Pure path helpers that propagate taint from arguments (path.join(base, input) is still tainted). */
export const ARG_PASSTHROUGH = /^(?:path\.(?:join|resolve|normalize|posix\.join|win32\.join)|String|JSON\.parse|Buffer\.from|decodeURIComponent|decodeURI|unescape|atob|util\.format|format|new URL|URL|Object\.assign|Object\.values|Object\.entries|Array\.from|structuredClone)$/;

export const ARRAY_CALLBACK_METHODS = new Set(["map", "forEach", "filter", "find", "some", "every", "flatMap", "reduce", "findLast"]);

export interface SinkSpec {
  id: string;
  title: string;
  severity: Severity;
  confidence: number;
  category: FindingCategory;
  cwe: string[];
  owasp: string;
  description: string;
  remediation: string;
  /** Matches the normalised callee text (e.g. `child_process.exec`, `res.redirect`). */
  callee: RegExp;
  /** Argument positions that must not receive tainted data; "any" checks all. */
  args: number[] | "any";
  /** Applies to `new X(...)` instead of plain calls. */
  isNew?: boolean;
}

const DB_OBJECT = "(?:db|database|sqlite|conn|connection|pool|client|knex|sequelize|tx|trx|stmt|sql|pg|mysql|prisma|this\\.db)";

export const SINKS: SinkSpec[] = [
  {
    id: "AEG-TAINT-CMD",
    title: "Command injection",
    severity: "critical",
    confidence: 0.95,
    category: "injection",
    cwe: ["CWE-78"],
    owasp: OWASP.injection,
    // Only the command / binary position matters: argument arrays passed to execFile/spawn are not shell-parsed.
    callee: /^(?:(?:child_process|childProcess|cp|proc|shell)\.)?(?:exec|execSync)$|(?:^|\.)(?:spawn|spawnSync|execFile|execFileSync|execa|execaCommand|execaSync)$/,
    args: [0],
    description: "Untrusted input reaches a process-execution API. An attacker can run arbitrary commands with the server's privileges.",
    remediation: "Never build shell strings from input. Use execFile/spawn with a fixed binary and an argument array, and allowlist permitted values.",
  },
  {
    id: "AEG-TAINT-CODE",
    title: "Code injection",
    severity: "critical",
    confidence: 0.95,
    category: "injection",
    cwe: ["CWE-94", "CWE-95"],
    owasp: OWASP.injection,
    callee: /^(?:eval|(?:window\.|globalThis\.)?(?:setTimeout|setInterval)|vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction))$/,
    args: [0],
    description: "Untrusted input is evaluated as JavaScript, giving the attacker arbitrary code execution.",
    remediation: "Remove dynamic evaluation. Parse data as data (JSON.parse + schema) and dispatch through explicit maps.",
  },
  {
    id: "AEG-TAINT-CODE",
    title: "Code injection via Function constructor",
    severity: "critical",
    confidence: 0.95,
    category: "injection",
    cwe: ["CWE-94", "CWE-95"],
    owasp: OWASP.injection,
    callee: /^(?:Function|vm\.Script)$/,
    args: "any",
    isNew: true,
    description: "Untrusted input is compiled into a function body.",
    remediation: "Replace dynamic code generation with ordinary functions.",
  },
  {
    id: "AEG-TAINT-CODE",
    title: "Code injection via Function()",
    severity: "critical",
    confidence: 0.9,
    category: "injection",
    cwe: ["CWE-94", "CWE-95"],
    owasp: OWASP.injection,
    callee: /^Function$/,
    args: "any",
    description: "Untrusted input is compiled into a function body.",
    remediation: "Replace dynamic code generation with ordinary functions.",
  },
  {
    id: "AEG-TAINT-SQL",
    title: "SQL injection",
    severity: "critical",
    confidence: 0.9,
    category: "injection",
    cwe: ["CWE-89"],
    owasp: OWASP.injection,
    callee: new RegExp(`(?:^|\\.)(?:query|execute|raw|\\$queryRawUnsafe|\\$executeRawUnsafe|unsafe|whereRaw|havingRaw|orderByRaw)$|^${DB_OBJECT}\\.(?:run|all|get|exec|prepare|each)$`),
    args: [0],
    description: "Untrusted input is concatenated into a SQL statement, letting an attacker read, modify or delete arbitrary data.",
    remediation: "Bind values as parameters (`$1` / `?`) or use a tagged-template builder (sql`...`) that parameterises interpolations.",
  },
  {
    id: "AEG-TAINT-NOSQL",
    title: "NoSQL operator injection",
    severity: "high",
    confidence: 0.6,
    category: "injection",
    cwe: ["CWE-943"],
    owasp: OWASP.injection,
    callee: /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|\$where)$/,
    args: [0],
    description: "A request-controlled object is used as a MongoDB filter. Payloads such as {\"$ne\": null} bypass equality checks (authentication bypass).",
    remediation: "Cast fields to primitives (String(x)), validate with a schema, or enable sanitizeFilter / express-mongo-sanitize.",
  },
  {
    id: "AEG-TAINT-PATH",
    title: "Path traversal",
    severity: "high",
    confidence: 0.85,
    category: "path-traversal",
    cwe: ["CWE-22"],
    owasp: OWASP.accessControl,
    callee: /^(?:(?:fs|fsp|fse|promises|fs\.promises|fsPromises)\.)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|open|openSync|copyFile|rename|mkdir|stat|lstat|access)$|^(?:res|reply|ctx|response)\.(?:sendFile|download|attachment)$/,
    args: [0],
    description: "Untrusted input selects a filesystem path. Sequences like ../../etc/passwd escape the intended directory.",
    remediation: "Resolve against a fixed root, then verify the result still starts with that root (path.resolve(root, p).startsWith(root + path.sep)), or map IDs to files.",
  },
  {
    id: "AEG-TAINT-SSRF",
    title: "Server-side request forgery",
    severity: "high",
    confidence: 0.85,
    category: "ssrf",
    cwe: ["CWE-918"],
    owasp: OWASP.accessControl,
    callee: /^(?:fetch|axios|got|request|superagent|needle|ky|ofetch|\$fetch|undici\.(?:request|fetch))$|^(?:axios|got|http|https|ky|superagent|needle|request)\.(?:get|post|put|patch|delete|head|request)$/,
    args: [0],
    description: "Untrusted input controls the URL of an outbound request, letting an attacker reach internal services or cloud metadata (169.254.169.254).",
    remediation: "Allowlist hosts, resolve DNS and block private/link-local ranges, and disable redirects for user-supplied URLs.",
  },
  {
    id: "AEG-TAINT-REDIRECT",
    title: "Open redirect",
    severity: "medium",
    confidence: 0.85,
    category: "redirect",
    cwe: ["CWE-601"],
    owasp: OWASP.accessControl,
    callee: /^(?:res|reply|ctx|response|NextResponse|Response|c)\.redirect$|^(?:redirect|permanentRedirect)$|^(?:window\.)?location\.(?:assign|replace)$/,
    args: "any",
    description: "Untrusted input chooses a redirect target, enabling convincing phishing links on your domain.",
    remediation: "Only redirect to relative paths or an allowlist of destinations.",
  },
  {
    id: "AEG-TAINT-XSS",
    title: "Cross-site scripting",
    severity: "high",
    confidence: 0.85,
    category: "xss",
    cwe: ["CWE-79"],
    owasp: OWASP.injection,
    callee: /^document\.(?:write|writeln)$|\.insertAdjacentHTML$|^\$\(.*\)\.(?:html|append|prepend|after|before)$/,
    args: "any",
    description: "Untrusted input is written into the page as HTML, allowing script execution in other users' sessions.",
    remediation: "Write text (textContent), use framework auto-escaping, or sanitise HTML with DOMPurify.",
  },
  {
    id: "AEG-TAINT-REDOS",
    title: "Regular-expression injection (ReDoS)",
    severity: "medium",
    confidence: 0.8,
    category: "dos",
    cwe: ["CWE-1333", "CWE-730"],
    owasp: OWASP.injection,
    callee: /^RegExp$/,
    args: [0],
    isNew: true,
    description: "Untrusted input is compiled as a regular expression; a crafted pattern causes catastrophic backtracking and blocks the event loop.",
    remediation: "Escape input (escapeRegExp), cap its length, or use RE2.",
  },
  {
    id: "AEG-TAINT-SSTI",
    title: "Server-side template injection",
    severity: "critical",
    confidence: 0.85,
    category: "injection",
    cwe: ["CWE-1336"],
    owasp: OWASP.injection,
    callee: /^(?:ejs\.render|ejs\.compile|Handlebars\.compile|handlebars\.compile|pug\.render|pug\.compile|nunjucks\.renderString|_\.template|lodash\.template|template|Mustache\.render|dot\.template)$/,
    args: [0],
    description: "Untrusted input is compiled as a template, which typically leads to remote code execution.",
    remediation: "Treat templates as code: load them from files and pass user data only as template variables.",
  },
  {
    id: "AEG-TAINT-DESER",
    title: "Unsafe deserialisation",
    severity: "critical",
    confidence: 0.85,
    category: "deserialization",
    cwe: ["CWE-502"],
    owasp: OWASP.integrity,
    callee: /^(?:serialize\.unserialize|unserialize|yaml\.load|YAML\.load|jsyaml\.load|v8\.deserialize|bson\.deserialize)$/,
    args: [0],
    description: "Untrusted bytes are deserialised with a format that can instantiate code or arbitrary objects.",
    remediation: "Use JSON.parse with schema validation; for YAML use the safe/core schema.",
  },
  {
    id: "AEG-TAINT-PROTO",
    title: "Prototype pollution via deep merge",
    severity: "medium",
    confidence: 0.65,
    category: "prototype-pollution",
    cwe: ["CWE-1321"],
    owasp: OWASP.injection,
    callee: /^(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)$|^(?:merge|deepMerge|mergeDeep|deepmerge|extend|set|setValue|dset)$/,
    args: "any",
    description: "A request-controlled object is deep-merged; a payload containing __proto__ alters Object.prototype for the whole process.",
    remediation: "Validate input with a strict schema and reject __proto__/constructor/prototype keys, or merge into Object.create(null).",
  },
];

/** Property-assignment sinks: `el.innerHTML = tainted`, `location.href = tainted`. */
export const ASSIGNMENT_SINKS: Array<{ target: RegExp; sink: SinkSpec }> = [
  {
    target: /\.(?:innerHTML|outerHTML|srcdoc)$/,
    sink: {
      ...SINKS.find((s) => s.id === "AEG-TAINT-XSS")!,
      title: "DOM-based cross-site scripting",
    },
  },
  {
    target: /^(?:window\.|document\.)?location(?:\.href)?$/,
    sink: {
      ...SINKS.find((s) => s.id === "AEG-TAINT-REDIRECT")!,
      title: "Client-side open redirect / javascript: URL",
      description: "Untrusted input is assigned to location. A javascript: URL executes script; any other URL is an open redirect.",
    },
  },
];

export const RESPONSE_WRITERS = /^(?:res|reply|response|ctx)\.(?:send|write|end)$|^(?:new )?Response$/;
