import { describe, expect, it } from "vitest";
import { buildViews, LineIndex } from "../src/lib/engine/lexer";

describe("lexer", () => {
  it("masks comments and string contents without moving offsets", () => {
    const src = 'const a = "eval(x)"; // eval(y)\n/* exec(z)\n */ run(a)';
    const v = buildViews(src, "typescript");
    expect(v.noComments.length).toBe(src.length);
    expect(v.codeOnly.length).toBe(src.length);
    expect(v.noComments.split("\n").length).toBe(3);
    expect(v.noComments).toContain('"eval(x)"');
    expect(v.noComments).not.toContain("eval(y)");
    expect(v.codeOnly).not.toContain("eval(x)");
    expect(v.codeOnly).toContain("run(a)");
    expect(v.commentLines).toBe(3);
  });

  it("keeps template-literal expressions as code", () => {
    const v = buildViews("exec(`ls ${dir} -la`)", "javascript");
    expect(v.codeOnly).toContain("${dir}");
    expect(v.codeOnly).not.toContain("ls");
    expect(v.codeOnly).not.toContain("-la");
  });

  it("masks regex literal bodies so quotes inside them don't desync the scanner", () => {
    const v = buildViews("const r = /['\"]eval\\(/g; const s = 'ok';", "javascript");
    expect(v.noComments).not.toContain("eval");
    expect(v.noComments).toContain("'ok'");
  });

  it("understands Python comments and triple-quoted strings", () => {
    const v = buildViews('x = 1  # eval(a)\ns = """\nos.system(b)\n"""\n', "python");
    expect(v.noComments).not.toContain("eval(a)");
    expect(v.codeOnly).not.toContain("os.system");
    expect(v.noComments).toContain("os.system");
  });

  it("maps offsets to line/column", () => {
    const idx = new LineIndex("ab\ncd\nef");
    expect(idx.position(0)).toEqual({ line: 1, column: 1 });
    expect(idx.position(4)).toEqual({ line: 2, column: 2 });
    expect(idx.lineText(3)).toBe("ef");
  });
});
