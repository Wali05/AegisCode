import type { Finding, RuleMeta } from "./types";
import type { LineIndex } from "./lexer";
import { makeFinding } from "./finding";
import { OWASP } from "./rules/patterns";

interface SecretRule extends RuleMeta {
  pattern: RegExp;
  confidence: number;
  /** Index of the capture group holding the secret value (0 = whole match). */
  group: number;
  /** Minimum Shannon entropy (bits/char) the captured value must reach. */
  minEntropy?: number;
}

const base = {
  category: "secrets" as const,
  cwe: ["CWE-798"],
  owasp: OWASP.auth,
  languages: "*" as const,
  detector: "secret" as const,
  remediation:
    "Revoke and rotate the credential now — it is in git history even if you delete it. Load secrets from the environment or a secret manager, and add a pre-commit secret scanner.",
};

export const SECRET_RULES: SecretRule[] = [
  { ...base, id: "AEG-SEC-001", title: "AWS access key ID", severity: "critical", confidence: 0.9, group: 0, pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/, description: "An AWS access key ID is committed to source." },
  { ...base, id: "AEG-SEC-002", title: "AWS secret access key", severity: "critical", confidence: 0.85, group: 1, minEntropy: 3.5, pattern: /aws.{0,24}?(?:secret|private).{0,24}?['"]([A-Za-z0-9/+=]{40})['"]/i, description: "An AWS secret access key is committed to source." },
  { ...base, id: "AEG-SEC-003", title: "GitHub token", severity: "critical", confidence: 0.95, group: 0, pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/, description: "A GitHub personal access / OAuth / app token is committed to source." },
  { ...base, id: "AEG-SEC-004", title: "Slack token or webhook", severity: "high", confidence: 0.9, group: 0, pattern: /\bxox[baprse]-[A-Za-z0-9-]{10,}\b|https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, description: "A Slack credential is committed to source." },
  { ...base, id: "AEG-SEC-005", title: "Stripe live secret key", severity: "critical", confidence: 0.95, group: 0, pattern: /\b[rs]k_live_[0-9a-zA-Z]{20,}\b/, description: "A live Stripe secret/restricted key can move money on your account." },
  { ...base, id: "AEG-SEC-006", title: "Google API key", severity: "high", confidence: 0.85, group: 0, pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, description: "A Google Cloud / Gemini API key is committed to source." },
  { ...base, id: "AEG-SEC-007", title: "OpenAI API key", severity: "critical", confidence: 0.9, group: 0, pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}\b|\bsk-proj-[A-Za-z0-9_-]{40,}\b/, description: "An OpenAI API key is committed to source." },
  { ...base, id: "AEG-SEC-008", title: "Anthropic API key", severity: "critical", confidence: 0.95, group: 0, pattern: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/, description: "An Anthropic API key is committed to source." },
  { ...base, id: "AEG-SEC-009", title: "Private key material", severity: "critical", confidence: 0.95, group: 0, cwe: ["CWE-321"], pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/, description: "A PEM/OpenSSH private key is embedded in the file." },
  { ...base, id: "AEG-SEC-010", title: "Hardcoded JSON Web Token", severity: "medium", confidence: 0.6, group: 0, pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, description: "A signed JWT is embedded in source; it may still be valid." },
  { ...base, id: "AEG-SEC-011", title: "Credentials in connection string", severity: "high", confidence: 0.85, group: 1, pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql):\/\/[^:\s'"/@]+:([^@\s'"]{3,})@[^\s'"]+/i, description: "A database / broker URL contains an inline password." },
  { ...base, id: "AEG-SEC-012", title: "SendGrid / Twilio / npm / Hugging Face token", severity: "high", confidence: 0.9, group: 0, pattern: /\bSG\.[\w-]{22}\.[\w-]{43}\b|\bSK[0-9a-f]{32}\b|\bnpm_[A-Za-z0-9]{36}\b|\bhf_[A-Za-z]{34}\b|\bsb_secret_[A-Za-z0-9_-]{20,}\b/, description: "A third-party service token is committed to source." },
  {
    ...base,
    id: "AEG-SEC-100",
    title: "High-entropy secret assigned to a sensitive name",
    severity: "high",
    confidence: 0.6,
    group: 2,
    minEntropy: 3.2,
    pattern: /\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|signing[_-]?key)[A-Za-z0-9_.-]*)['"]?\s*(?:[:=]|:=|=>)\s*['"`]([^'"`\s]{8,})['"`]/i,
    description: "A literal value with secret-like entropy is assigned to a credential-named variable.",
  },
];

const PLACEHOLDER = /^(?:x{3,}|\*{3,}|\.{3,}|<.*>|\$\{.*\}|\{\{.*\}\}|%\w+%|your[_-]|change[_-]?me|example|placeholder|dummy|sample|redacted|replace[_-]?me|insert[_-]|todo|none|null|undefined|test|fake|mock)/i;

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function redact(secret: string): string {
  if (secret.length <= 8) return "•".repeat(secret.length);
  return `${secret.slice(0, 4)}${"•".repeat(Math.min(12, secret.length - 6))}${secret.slice(-2)}`;
}

function looksLikeFixture(path: string): boolean {
  return /(^|\/)(tests?|__tests__|spec|fixtures?|examples?|samples?|mocks?|testdata)(\/|$)|\.(test|spec)\.|\.example$|\.sample$/i.test(path);
}

/**
 * Detects committed credentials. Runs on the raw source (comments included —
 * a key in a comment is still leaked). Values are redacted before they leave
 * the engine so reports can be shared safely.
 */
export function scanSecrets(raw: string, file: string, index: LineIndex): Finding[] {
  const out: Finding[] = [];
  const fixtureFactor = looksLikeFixture(file) ? 0.5 : 1;
  const claimed = new Set<string>();

  for (const rule of SECRET_RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");
    for (const m of raw.matchAll(re)) {
      if (m.index === undefined) continue;
      const value = m[rule.group] ?? m[0];
      if (claimed.has(value)) continue; // a specific rule already reported this value
      if (PLACEHOLDER.test(value) || /^(?:process\.env|os\.environ|getenv|env\()/i.test(value)) continue;
      const entropy = shannonEntropy(value);
      if (rule.minEntropy && entropy < rule.minEntropy) continue;

      const valueOffset = m.index + m[0].indexOf(value);
      const start = index.position(valueOffset);
      const end = index.position(valueOffset + value.length);
      const line = index.lineText(start.line);
      let confidence = rule.confidence * fixtureFactor;
      if (rule.id === "AEG-SEC-100") confidence = Math.min(0.85, confidence + (entropy - 3.2) * 0.15);

      claimed.add(value);
      out.push(
        makeFinding({
          rule,
          file,
          location: { line: start.line, column: start.column, endLine: end.line, endColumn: end.column },
          snippet: line.split(value).join(redact(value)),
          confidence,
          detector: "secret",
          description: `${rule.description} Entropy ${entropy.toFixed(2)} bits/char.`,
        })
      );
    }
  }
  return out;
}
