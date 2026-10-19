import { AuditApp } from "@/components/audit/AuditApp";
import { Hero, Landing } from "@/components/marketing/Landing";
import { Footer, Nav } from "@/components/site";

export default async function Home({ searchParams }: PageProps<"/">) {
  // ?target=<github url> pre-fills the console so audits are linkable.
  const { target } = await searchParams;
  return (
    <>
      <Nav />
      <AuditApp hero={<Hero />} initialUrl={typeof target === "string" ? target.slice(0, 2048) : undefined}>
        <Landing />
      </AuditApp>
      <Footer />
    </>
  );
}
