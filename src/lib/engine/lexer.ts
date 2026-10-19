import type { Language } from "./types";
import { isCLike, isJsFamily } from "./language";

export interface SourceViews {
  raw: string;
  /** Comments replaced by spaces. Offsets and line numbers are identical to `raw`. */
  noComments: string;
  /** Comments and string-literal contents replaced by spaces (quotes are kept). */
  codeOnly: string;
  commentLines: number;
}

interface Syntax {
  line: string[];
  block: [string, string] | null;
  quotes: string[];
  triple: boolean;
  template: boolean;
  regex: boolean;
}

function syntaxFor(lang: Language): Syntax {
  if (lang === "python") return { line: ["#"], block: null, quotes: ["'", '"'], triple: true, template: false, regex: false };
  if (lang === "ruby" || lang === "shell") return { line: ["#"], block: null, quotes: ["'", '"'], triple: false, template: false, regex: false };
  if (lang === "php") return { line: ["//", "#"], block: ["/*", "*/"], quotes: ["'", '"'], triple: false, template: false, regex: false };
  if (isCLike(lang)) {
    const js = isJsFamily(lang);
    return {
      line: ["//"],
      block: ["/*", "*/"],
      quotes: lang === "go" || js ? ["'", '"', "`"] : ["'", '"'],
      triple: false,
      template: js,
      regex: js,
    };
  }
  return { line: [], block: null, quotes: [], triple: false, template: false, regex: false };
}

const REGEX_PRECEDERS = new Set(["(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^"]);

/**
 * A small single-pass scanner that understands comments, string literals,
 * JS template literals (with nested `${}` expressions) and JS regex literals.
 * It is deliberately offset-preserving: every masked character becomes a
 * space and newlines are kept, so findings map 1:1 onto the original file.
 */
export function buildViews(raw: string, lang: Language): SourceViews {
  const syn = syntaxFor(lang);
  const n = raw.length;
  const noComments = raw.split("");
  const codeOnly = raw.split("");
  const commentLineSet = new Set<number>();

  let line = 1;
  let i = 0;
  // Stack of brace depths for template-literal `${ ... }` expressions.
  const templateStack: number[] = [];
  let braceDepth = 0;
  let lastSignificant = "";

  const blank = (arr: string[], from: number, to: number) => {
    for (let k = from; k < to; k++) if (arr[k] !== "\n") arr[k] = " ";
  };
  const countLines = (from: number, to: number) => {
    for (let k = from; k < to; k++) if (raw[k] === "\n") line++;
  };

  const scanTemplate = (start: number): number => {
    // `start` points just after the opening backtick (or after a closing `}`).
    let k = start;
    while (k < n) {
      const c = raw[k];
      if (c === "\\") {
        k += 2;
        continue;
      }
      if (c === "`") {
        blank(codeOnly, start, k);
        return k + 1;
      }
      if (c === "$" && raw[k + 1] === "{") {
        blank(codeOnly, start, k);
        templateStack.push(braceDepth);
        braceDepth++;
        return k + 2;
      }
      k++;
    }
    blank(codeOnly, start, n);
    return n;
  };

  while (i < n) {
    const c = raw[i];

    if (c === "\n") {
      line++;
      i++;
      continue;
    }

    // Line comments
    const lineTok = syn.line.find((t) => raw.startsWith(t, i));
    if (lineTok && !(lineTok === "#" && lang === "php" && raw[i + 1] === "[")) {
      let end = raw.indexOf("\n", i);
      if (end === -1) end = n;
      blank(noComments, i, end);
      blank(codeOnly, i, end);
      commentLineSet.add(line);
      i = end;
      continue;
    }

    // Block comments
    if (syn.block && raw.startsWith(syn.block[0], i)) {
      let end = raw.indexOf(syn.block[1], i + syn.block[0].length);
      end = end === -1 ? n : end + syn.block[1].length;
      const startLine = line;
      countLines(i, end);
      for (let l = startLine; l <= line; l++) commentLineSet.add(l);
      blank(noComments, i, end);
      blank(codeOnly, i, end);
      i = end;
      continue;
    }

    // Python triple-quoted strings
    if (syn.triple && (raw.startsWith('"""', i) || raw.startsWith("'''", i))) {
      const q = raw.slice(i, i + 3);
      let end = raw.indexOf(q, i + 3);
      end = end === -1 ? n : end + 3;
      countLines(i, end);
      blank(codeOnly, i + 3, Math.max(i + 3, end - 3));
      i = end;
      lastSignificant = "s";
      continue;
    }

    // Template literals
    if (syn.template && c === "`") {
      const end = scanTemplate(i + 1);
      countLines(i, end);
      i = end;
      lastSignificant = "s";
      continue;
    }

    if (syn.template && templateStack.length > 0) {
      if (c === "{") braceDepth++;
      if (c === "}") {
        braceDepth--;
        if (braceDepth === templateStack[templateStack.length - 1]) {
          templateStack.pop();
          const end = scanTemplate(i + 1);
          countLines(i, end);
          i = end;
          lastSignificant = "s";
          continue;
        }
      }
    }

    // Ordinary string literals
    if (syn.quotes.includes(c)) {
      let k = i + 1;
      while (k < n && raw[k] !== c) {
        if (raw[k] === "\\") k++;
        else if (raw[k] === "\n" && c !== "`") break; // unterminated
        k++;
      }
      const end = Math.min(k + 1, n);
      countLines(i, end);
      blank(codeOnly, i + 1, Math.max(i + 1, end - 1));
      i = end;
      lastSignificant = "s";
      continue;
    }

    // JS regex literals — skipped so quotes inside them don't confuse the scanner.
    if (syn.regex && c === "/" && (lastSignificant === "" || REGEX_PRECEDERS.has(lastSignificant) || lastSignificant === "return")) {
      let k = i + 1;
      let inClass = false;
      while (k < n && raw[k] !== "\n") {
        if (raw[k] === "\\") k += 2;
        else if (raw[k] === "[") {
          inClass = true;
          k++;
        } else if (raw[k] === "]") {
          inClass = false;
          k++;
        }
        else if (raw[k] === "/" && !inClass) break;
        else k++;
      }
      if (raw[k] === "/") {
        // Regex bodies are data, not code: mask them in both views so rules never match pattern text.
        blank(noComments, i + 1, k);
        blank(codeOnly, i + 1, k);
        k++;
        while (k < n && /[a-z]/i.test(raw[k])) k++;
        i = k;
        lastSignificant = "s";
        continue;
      }
    }

    if (!/\s/.test(c)) {
      if (/[A-Za-z_$]/.test(c)) {
        const m = /^[A-Za-z_$][\w$]*/.exec(raw.slice(i, i + 32));
        const word = m ? m[0] : c;
        lastSignificant = word === "return" || word === "typeof" ? "return" : "w";
        i += word.length;
        continue;
      }
      lastSignificant = c;
    }
    i++;
  }

  return {
    raw,
    noComments: noComments.join(""),
    codeOnly: codeOnly.join(""),
    commentLines: commentLineSet.size,
  };
}

/** Precomputed newline offsets for O(log n) offset → line/column lookups. */
export class LineIndex {
  private starts: number[] = [0];
  constructor(private text: string) {
    for (let i = 0; i < text.length; i++) if (text[i] === "\n") this.starts.push(i + 1);
  }
  get lineCount(): number {
    return this.starts.length;
  }
  position(offset: number): { line: number; column: number } {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - this.starts[lo] + 1 };
  }
  lineStart(line: number): number {
    return this.starts[line - 1] ?? this.text.length;
  }
  lineText(line: number): string {
    const start = this.starts[line - 1] ?? 0;
    const end = this.starts[line] ?? this.text.length + 1;
    return this.text.slice(start, end - 1);
  }
}
