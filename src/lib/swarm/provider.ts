import { GoogleGenAI, ApiError, type GenerateContentResponse } from "@google/genai";
import { z } from "zod";

export interface Usage {
  inputTokens: number;
  outputTokens: number;
}

export interface GenerateRequest<T> {
  system: string;
  prompt: string;
  schema: z.ZodType<T>;
  temperature?: number;
  signal?: AbortSignal;
}

export interface GenerateResult<T> {
  data: T;
  usage: Usage;
  ms: number;
  repaired: boolean;
}

/** Minimal provider contract — any model that can emit schema-constrained JSON can run the swarm. */
export interface LlmProvider {
  readonly name: string;
  readonly model: string;
  generate<T>(req: GenerateRequest<T>): Promise<GenerateResult<T>>;
}

function toJsonSchema(schema: z.ZodType): Record<string, unknown> {
  const json = z.toJSONSchema(schema, { target: "draft-2020-12" }) as Record<string, unknown>;
  delete json.$schema;
  return json;
}

function extractJson(text: string): unknown {
  const trimmed = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "");
  try {
    return JSON.parse(trimmed);
  } catch {
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start >= 0 && end > start) return JSON.parse(trimmed.slice(start, end + 1));
    throw new Error("Model did not return JSON.");
  }
}

export class GeminiProvider implements LlmProvider {
  readonly name = "gemini";
  private client: GoogleGenAI;
  private nativeSchema = true;

  constructor(apiKey: string, readonly model: string) {
    this.client = new GoogleGenAI({ apiKey });
  }

  private async call(req: GenerateRequest<unknown>, prompt: string): Promise<GenerateContentResponse> {
    const schema = toJsonSchema(req.schema);
    try {
      return await this.client.models.generateContent({
        model: this.model,
        contents: prompt,
        config: {
          systemInstruction: req.system,
          temperature: req.temperature ?? 0.2,
          responseMimeType: "application/json",
          ...(this.nativeSchema ? { responseJsonSchema: schema } : {}),
          abortSignal: req.signal,
        },
      });
    } catch (err) {
      // Older models reject some JSON-Schema keywords; fall back to prompt-described schema once.
      if (this.nativeSchema && err instanceof ApiError && err.status === 400 && /schema/i.test(err.message)) {
        this.nativeSchema = false;
        return this.call(req, `${prompt}\n\nRespond with JSON matching this JSON Schema exactly:\n${JSON.stringify(schema)}`);
      }
      throw err;
    }
  }

  async generate<T>(req: GenerateRequest<T>): Promise<GenerateResult<T>> {
    const t0 = Date.now();
    const usage: Usage = { inputTokens: 0, outputTokens: 0 };
    let prompt = req.prompt;
    let repaired = false;

    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await this.call(req as GenerateRequest<unknown>, prompt);
      usage.inputTokens += res.usageMetadata?.promptTokenCount ?? 0;
      usage.outputTokens += (res.usageMetadata?.candidatesTokenCount ?? 0) + (res.usageMetadata?.thoughtsTokenCount ?? 0);
      const text = res.text ?? "";
      let issue: string;
      try {
        const parsed = req.schema.safeParse(extractJson(text));
        if (parsed.success) return { data: parsed.data, usage, ms: Date.now() - t0, repaired };
        issue = z.prettifyError(parsed.error);
      } catch (e) {
        issue = e instanceof Error ? e.message : "invalid JSON";
      }
      // One self-repair round: show the model its own output and the validation error.
      repaired = true;
      prompt = `${req.prompt}\n\nYour previous answer failed validation:\n${issue}\n\nPrevious answer (truncated):\n${text.slice(0, 4000)}\n\nReturn corrected JSON only.`;
    }
    throw new Error("The model returned malformed output twice.");
  }
}

export function providerFromEnv(): LlmProvider | null {
  const key = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!key) return null;
  return new GeminiProvider(key, process.env.GEMINI_MODEL || "gemini-flash-latest");
}
