import { z } from "zod";

const severity = z.enum(["critical", "high", "medium", "low", "info"]);

export const ClaimSchema = z.object({
  id: z.string().describe("Sequential id: C1, C2, …"),
  title: z.string().describe("Short, specific title, e.g. 'IDOR: any user can read any invoice'"),
  severity,
  category: z.enum(["injection", "xss", "secrets", "crypto", "ssrf", "path-traversal", "deserialization", "auth", "config", "dos", "prototype-pollution", "redirect", "memory-safety", "code-quality", "performance"]),
  cwe: z.string().describe("Most specific CWE id, e.g. CWE-639"),
  line_start: z.number().int(),
  line_end: z.number().int(),
  evidence: z.string().describe("Verbatim code copied from the file that demonstrates the issue (1-3 lines)."),
  exploit: z.string().describe("Concrete attack or failure scenario, including an example payload where applicable."),
  related_finding: z.string().describe("Id of the static-analysis finding this confirms, or an empty string for a new issue."),
});

export const CriticSchema = z.object({
  claims: z.array(ClaimSchema).max(14),
});

export const DefenderSchema = z.object({
  responses: z.array(
    z.object({
      claim_id: z.string(),
      stance: z.enum(["concede", "dispute", "mitigate"]).describe("concede = real issue; dispute = false positive; mitigate = real but already partly mitigated / lower impact"),
      argument: z.string().describe("Technical argument grounded in the code."),
      fix: z.string().describe("Minimal code change that fixes the issue, or empty string if disputed."),
    })
  ),
});

export const JudgeSchema = z.object({
  rulings: z.array(
    z.object({
      claim_id: z.string(),
      upheld: z.boolean(),
      severity,
      confidence: z.number().min(0).max(1),
      rationale: z.string().describe("One or two sentences explaining the ruling."),
    })
  ),
  summary: z.string().describe("3-5 sentence executive summary of the file's security posture."),
  patched_code: z.string().describe("The complete file with every upheld issue fixed. Preserve formatting, comments and behaviour otherwise. Empty string if nothing was upheld."),
});

export type Claim = z.infer<typeof ClaimSchema>;
export type CriticOutput = z.infer<typeof CriticSchema>;
export type DefenderOutput = z.infer<typeof DefenderSchema>;
export type JudgeOutput = z.infer<typeof JudgeSchema>;
