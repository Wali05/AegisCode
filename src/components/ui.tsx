"use client";

import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { AlertOctagon, AlertTriangle, CircleAlert, Info, ShieldAlert } from "lucide-react";
import type { Severity } from "@/lib/engine/types";

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export const SEVERITY_META: Record<Severity, { label: string; text: string; bg: string; ring: string; dot: string; hex: string; Icon: typeof Info }> = {
  critical: { label: "Critical", text: "text-sev-critical", bg: "bg-sev-critical/12", ring: "ring-sev-critical/30", dot: "bg-sev-critical", hex: "#e8417f", Icon: AlertOctagon },
  high: { label: "High", text: "text-sev-high", bg: "bg-sev-high/12", ring: "ring-sev-high/30", dot: "bg-sev-high", hex: "#f07c2a", Icon: ShieldAlert },
  medium: { label: "Medium", text: "text-sev-medium", bg: "bg-sev-medium/12", ring: "ring-sev-medium/30", dot: "bg-sev-medium", hex: "#e5c13c", Icon: AlertTriangle },
  low: { label: "Low", text: "text-sev-low", bg: "bg-sev-low/12", ring: "ring-sev-low/30", dot: "bg-sev-low", hex: "#3e8bf0", Icon: CircleAlert },
  info: { label: "Info", text: "text-sev-info", bg: "bg-sev-info/12", ring: "ring-sev-info/30", dot: "bg-sev-info", hex: "#7d828c", Icon: Info },
};

export function SeverityBadge({ severity, className, compact }: { severity: Severity; className?: string; compact?: boolean }) {
  const m = SEVERITY_META[severity];
  return (
    <span className={cn("inline-flex shrink-0 items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", m.bg, m.text, m.ring, className)}>
      <m.Icon className="size-3" aria-hidden />
      {compact ? m.label[0] : m.label}
    </span>
  );
}

export function Badge({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cn("inline-flex items-center gap-1 rounded-md border border-line bg-s2 px-1.5 py-0.5 font-mono text-[11px] text-fg-2", className)}>
      {children}
    </span>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" | "outline"; size?: "sm" | "md" };

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button({ variant = "outline", size = "md", className, ...props }, ref) {
  return (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-[background,color,box-shadow,transform] duration-150 select-none active:scale-[0.98] disabled:pointer-events-none disabled:opacity-40",
        size === "sm" ? "h-8 px-2.5 text-[12.5px]" : "h-10 px-4 text-sm",
        variant === "primary" && "bg-accent text-accent-ink shadow-[0_0_0_1px_rgb(198_244_50/0.5),0_8px_30px_-8px_rgb(198_244_50/0.55)] hover:bg-[#d4ff4a]",
        variant === "outline" && "border border-line-strong bg-s2 text-fg hover:bg-s3",
        variant === "ghost" && "text-fg-2 hover:bg-s2 hover:text-fg",
        className
      )}
      {...props}
    />
  );
});

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden fill="none">
      <path d="M16 2.5 4.5 7v8.4c0 7 4.9 12.4 11.5 14.1 6.6-1.7 11.5-7.1 11.5-14.1V7L16 2.5Z" fill="url(#lg)" stroke="rgb(255 255 255 / .25)" strokeWidth="1" />
      <path d="M11 16.2 14.6 19.6 21.4 12.4" stroke="#0b0d04" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      <defs>
        <linearGradient id="lg" x1="6" y1="3" x2="26" y2="29" gradientUnits="userSpaceOnUse">
          <stop stopColor="#dcff6b" />
          <stop offset="1" stopColor="#8fb21f" />
        </linearGradient>
      </defs>
    </svg>
  );
}

export interface TabItem<T extends string> {
  id: T;
  label: string;
  count?: number;
  icon?: ReactNode;
  hidden?: boolean;
}

export function Tabs<T extends string>({ items, value, onChange, className }: { items: TabItem<T>[]; value: T; onChange: (id: T) => void; className?: string }) {
  return (
    <div role="tablist" className={cn("flex items-center gap-1 overflow-x-auto [scrollbar-width:none]", className)}>
      {items
        .filter((t) => !t.hidden)
        .map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={value === t.id}
            onClick={() => onChange(t.id)}
            className={cn(
              "relative inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg px-3 text-[13px] transition-colors",
              value === t.id ? "bg-s3 text-fg shadow-[inset_0_0_0_1px_rgb(255_255_255/0.08)]" : "text-fg-3 hover:text-fg-2"
            )}
          >
            {t.icon}
            {t.label}
            {t.count !== undefined && <span className={cn("rounded px-1 font-mono text-[10.5px]", value === t.id ? "bg-s4 text-fg-2" : "text-fg-3")}>{t.count}</span>}
          </button>
        ))}
    </div>
  );
}

export function Segmented<T extends string>({ options, value, onChange, label }: { options: Array<{ id: T; label: string; title?: string }>; value: T; onChange: (v: T) => void; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-lg border border-line bg-s2 p-0.5">
      {options.map((o) => (
        <button
          key={o.id}
          role="radio"
          aria-checked={value === o.id}
          title={o.title}
          onClick={() => onChange(o.id)}
          className={cn("h-7 rounded-md px-2.5 text-[12px] transition-colors", value === o.id ? "bg-s4 text-fg" : "text-fg-3 hover:text-fg-2")}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function SectionLabel({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("font-mono text-[11px] tracking-[0.14em] text-fg-3 uppercase", className)}>{children}</div>;
}

/** GitHub mark (brand icons are not part of lucide). */
export function GithubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor" aria-hidden>
      <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.52-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.56-.29-5.25-1.28-5.25-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.69 5.39-5.26 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" />
    </svg>
  );
}
