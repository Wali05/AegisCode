import type { Language } from "./types";

const EXTENSIONS: Record<string, Language> = {
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  jsx: "javascript",
  ts: "typescript",
  mts: "typescript",
  cts: "typescript",
  tsx: "typescript",
  py: "python",
  pyw: "python",
  go: "go",
  java: "java",
  kt: "java",
  php: "php",
  rb: "ruby",
  cs: "csharp",
  rs: "rust",
  c: "c",
  h: "c",
  cc: "cpp",
  cpp: "cpp",
  cxx: "cpp",
  hpp: "cpp",
  sh: "shell",
  bash: "shell",
  zsh: "shell",
  json: "json",
};

export function detectLanguage(path: string, code?: string): Language {
  const base = path.split("/").pop() ?? path;
  const ext = base.includes(".") ? base.split(".").pop()!.toLowerCase() : "";
  if (EXTENSIONS[ext]) return EXTENSIONS[ext];
  if (base === "Dockerfile" || base === "Makefile") return "shell";

  if (code) {
    const firstLine = code.slice(0, 200).split("\n")[0];
    if (/^#!.*\b(ba|z)?sh\b/.test(firstLine)) return "shell";
    if (/^#!.*python/.test(firstLine)) return "python";
    if (/^#!.*node/.test(firstLine)) return "javascript";
    // Cheap content sniffing for pasted snippets without a filename.
    if (/^\s*(def |import \w+$|from \w+ import)/m.test(code) && !/[;{]\s*$/m.test(code)) return "python";
    if (/^\s*package \w+\s*$/m.test(code) && /\bfunc\b/.test(code)) return "go";
    if (/<\?php/.test(code)) return "php";
    if (/\b(interface|type)\s+\w+\s*[={<]|:\s*(string|number|boolean)\b/.test(code)) return "typescript";
    if (/\b(const|let|function|=>|require\(|import .* from)\b/.test(code)) return "javascript";
    if (/#include\s*</.test(code)) return "c";
  }
  return "unknown";
}

export function isJsFamily(lang: Language): boolean {
  return lang === "javascript" || lang === "typescript";
}

/** Languages whose comment and string syntax follows C conventions. */
export function isCLike(lang: Language): boolean {
  return ["javascript", "typescript", "go", "java", "csharp", "rust", "c", "cpp", "php", "json"].includes(lang);
}

export const LANGUAGE_LABELS: Record<Language, string> = {
  javascript: "JavaScript",
  typescript: "TypeScript",
  python: "Python",
  go: "Go",
  java: "Java / Kotlin",
  php: "PHP",
  ruby: "Ruby",
  csharp: "C#",
  rust: "Rust",
  c: "C",
  cpp: "C++",
  shell: "Shell",
  json: "JSON",
  unknown: "Plain text",
};

export function isAnalyzablePath(path: string): boolean {
  return detectLanguage(path) !== "unknown";
}
