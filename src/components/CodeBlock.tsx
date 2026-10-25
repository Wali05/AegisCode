"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

export function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="panel overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-4 py-2">
        <span className="font-mono text-[11.5px] text-fg-3">{label ?? "shell"}</span>
        <button
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(code);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            } catch {
              /* clipboard unavailable */
            }
          }}
          className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11.5px] text-fg-2 hover:bg-s3 hover:text-fg"
        >
          {copied ? <Check className="size-3" /> : <Copy className="size-3" />} {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="code overflow-x-auto px-4 py-3 text-[12px] text-fg-2">{code}</pre>
    </div>
  );
}
