import { scanFile } from "../src/lib/engine";
import type { Finding } from "../src/lib/engine/types";

export const scan = (path: string, code: string) => scanFile(path, code);
export const ids = (findings: Finding[]) => findings.filter((f) => f.status !== "dismissed").map((f) => f.ruleId);
export const taint = (path: string, code: string) => scan(path, code).findings.filter((f) => f.detector === "taint");
