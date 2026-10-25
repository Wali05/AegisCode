import { ImageResponse } from "next/og";

export const alt = "AegisCode: security checks for code your AI wrote";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  const row = (color: string, label: string, text: string) => (
    <div style={{ display: "flex", alignItems: "center", gap: 14, fontSize: 22, color: "#a9adb5" }}>
      <div style={{ width: 12, height: 12, borderRadius: 999, background: color }} />
      <span style={{ color, width: 120 }}>{label}</span>
      <span>{text}</span>
    </div>
  );
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between", padding: 72, background: "radial-gradient(900px 420px at 50% -80px, rgba(198,244,50,0.18), transparent 70%), #08090a", color: "#edeef0", fontFamily: "sans-serif" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 30, fontWeight: 600 }}>
          <svg width="44" height="44" viewBox="0 0 32 32">
            <path d="M16 2.5 4.5 7v8.4c0 7 4.9 12.4 11.5 14.1 6.6-1.7 11.5-7.1 11.5-14.1V7L16 2.5Z" fill="#c6f432" />
            <path d="M11 16.2 14.6 19.6 21.4 12.4" stroke="#0b0d04" strokeWidth="2.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          AegisCode
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div style={{ fontSize: 76, fontWeight: 700, letterSpacing: -2, lineHeight: 1.05 }}>Security checks for code</div>
          <div style={{ fontSize: 76, fontWeight: 700, letterSpacing: -2, lineHeight: 1.05, color: "#c6f432" }}>your AI wrote.</div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {row("#f07c2a", "Traces", "untrusted input across files to the real sink")}
          {row("#e8417f", "Catches", "imported packages that don't exist")}
          {row("#c6f432", "Fixes", "and re-scans every fix before offering it")}
        </div>
      </div>
    ),
    size
  );
}
