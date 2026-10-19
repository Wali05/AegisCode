import type { PipelineEvent } from "../report/types";

export interface AuditRequest {
  url?: string;
  code?: string;
  filename?: string;
  swarm: "auto" | "force" | "off";
}

/**
 * POSTs an audit request and yields Server-Sent Events as they arrive.
 * (EventSource can't POST, so this parses the stream by hand.)
 */
export async function* streamAudit(req: AuditRequest, signal: AbortSignal): AsyncGenerator<PipelineEvent> {
  const res = await fetch("/api/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
    signal,
  });

  if (!res.ok || !res.body) {
    let message = `Request failed (${res.status})`;
    let hint: string | undefined;
    try {
      const body = (await res.json()) as { error?: string; hint?: string };
      message = body.error ?? message;
      hint = body.hint;
    } catch {
      /* non-JSON error body */
    }
    yield { type: "error", message, hint, status: res.status };
    return;
  }

  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    let sep: number;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      const data = frame
        .split("\n")
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).trimStart())
        .join("\n");
      if (data) yield JSON.parse(data) as PipelineEvent;
    }
  }
}
