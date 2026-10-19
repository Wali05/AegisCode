import { ENGINE_VERSION, RULE_COUNT } from "@/lib/pipeline";
import { githubToken, provider } from "@/lib/server/context";

export const runtime = "nodejs";

export function GET() {
  const llm = provider();
  return Response.json({
    ok: true,
    engine: { version: ENGINE_VERSION, rules: RULE_COUNT },
    swarm: llm ? { enabled: true, provider: llm.name, model: llm.model } : { enabled: false },
    github: { authenticated: !!githubToken() },
  });
}
