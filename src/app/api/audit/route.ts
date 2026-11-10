import { z } from "zod";
import { runAudit } from "@/lib/pipeline";
import { GitHubError } from "@/lib/github";
import type { PipelineEvent } from "@/lib/report/types";
import { cache, cacheKey, clientIp, github, limiter, provider } from "@/lib/server/context";

export const runtime = "nodejs";
export const maxDuration = 300;

const MAX_SNIPPET = 200_000;

const Body = z
  .object({
    url: z.string().trim().min(3, "That doesn't look like a GitHub URL or owner/repo.").max(2048, "The URL is too long.").optional(),
    code: z.string().max(MAX_SNIPPET, `Snippets are limited to ${MAX_SNIPPET / 1000} KB.`).optional(),
    filename: z
      .string()
      .trim()
      .max(200, "Filename is limited to 200 characters.")
      .regex(/^[\w./-]*$/, "Filename may only contain letters, digits, dot, dash, underscore and slash.")
      .optional(),
    swarm: z.enum(["auto", "force", "off"], "`swarm` must be auto, force or off.").default("auto"),
  })
  .refine((b) => !!b.url !== (b.code !== undefined), { message: "Provide either `url` or `code`, not both." })
  .refine((b) => b.code === undefined || b.code.trim().length > 0, { message: "The snippet is empty." });

/** MAX_REPO_FILES, kept to a sane range so a typo in the environment can't disable or explode repo scans. */
function maxRepoFiles(): number {
  const n = Number(process.env.MAX_REPO_FILES);
  return Number.isFinite(n) && n >= 1 ? Math.min(Math.floor(n), 400) : 40;
}

function json(status: number, body: Record<string, unknown>, headers?: HeadersInit) {
  return Response.json(body, { status, headers });
}

/**
 * Streams the audit pipeline as Server-Sent Events:
 *   event: stage | log | file | claim | report | error
 * The final `report` event carries the complete AuditReport.
 */
export async function POST(request: Request) {
  let body: z.infer<typeof Body>;
  try {
    const parsed = Body.safeParse(await request.json());
    if (!parsed.success) return json(400, { error: parsed.error.issues[0]?.message ?? "Invalid request." });
    body = parsed.data;
  } catch {
    return json(400, { error: "Request body must be JSON." });
  }

  const key = cacheKey([body.url ?? null, body.code ?? null, body.filename ?? null, body.swarm, !!provider()]);
  const cached = cache().get(key);

  if (!cached) {
    const rl = limiter().take(clientIp(request.headers));
    if (!rl.ok) return json(429, { error: "Rate limit reached.", hint: `Try again in ${rl.retryAfterSec}s.` }, { "Retry-After": String(rl.retryAfterSec) });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;
      const send = (e: PipelineEvent) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`));
        } catch {
          closed = true;
        }
      };
      // Comment frames keep proxies from closing an idle connection during long LLM calls.
      const heartbeat = setInterval(() => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(": keep-alive\n\n"));
        } catch {
          closed = true;
        }
      }, 15_000);

      try {
        if (cached) {
          for (const stage of cached.stages) send({ type: "stage", stage });
          send({ type: "log", level: "success", scope: "cache", message: "Identical audit found in cache — replaying result.", t: Date.now() });
          send({ type: "report", report: { ...cached, cached: true } });
        } else {
          const report = await runAudit(
            { url: body.url, code: body.code, filename: body.filename, swarm: body.swarm },
            { github: github(request.signal), provider: provider(), maxRepoFiles: maxRepoFiles(), signal: request.signal },
            send
          );
          cache().set(key, report);
          send({ type: "report", report });
        }
      } catch (err) {
        if (err instanceof GitHubError) send({ type: "error", message: err.message, hint: err.hint, status: err.status });
        else send({ type: "error", message: err instanceof Error ? err.message : "Unexpected error.", status: 500 });
      } finally {
        clearInterval(heartbeat);
        closed = true;
        try {
          controller.close();
        } catch {
          /* client already disconnected */
        }
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
