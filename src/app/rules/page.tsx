import type { Metadata } from "next";
import { ruleCatalog, catalogStats } from "@/lib/catalog";
import { LANGUAGE_LABELS } from "@/lib/engine/language";
import { Footer, Nav } from "@/components/site";
import { RuleTable } from "./RuleTable";

export const metadata: Metadata = {
  title: "Rule catalog",
  description: "Every detection rule in the AegisCode engine, mapped to CWE and the OWASP Top 10 (2025).",
};

export default function RulesPage() {
  const stats = catalogStats();
  const rules = ruleCatalog().map((r) => ({
    ...r,
    languages: r.languages === "*" ? "All languages" : r.languages.map((l) => LANGUAGE_LABELS[l]).join(", "),
  }));
  return (
    <>
      <Nav />
      <main className="mx-auto w-full max-w-7xl px-4 pt-14 pb-24 sm:px-6">
        <div className="max-w-2xl">
          <div className="font-mono text-[11px] tracking-[0.14em] text-accent uppercase">Rule catalog</div>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight">
            {stats.rules} rules. <span className="font-serif font-normal text-fg-2 italic">{stats.cwes} weakness classes.</span>
          </h1>
          <p className="mt-4 text-[15px] leading-relaxed text-fg-2">
            Taint sinks follow attacker-controlled data from source to sink; pattern rules flag dangerous constructs; secret rules combine provider signatures with entropy; quality rules catch
            performance cliffs and memory leaks. Everything is mapped to CWE and the OWASP Top 10 (2025).
          </p>
        </div>
        <RuleTable rules={rules} />
      </main>
      <Footer />
    </>
  );
}
