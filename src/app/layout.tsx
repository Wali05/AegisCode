import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono, Instrument_Serif } from "next/font/google";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });
const instrumentSerif = Instrument_Serif({ variable: "--font-instrument-serif", subsets: ["latin"], weight: "400", style: ["normal", "italic"] });

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000"),
  title: {
    default: "AegisCode — security review that argues with itself",
    template: "%s · AegisCode",
  },
  description:
    "An AST taint-analysis engine and an adversarial Critic → Defender → Judge LLM swarm. Every AI claim must quote your source or it is thrown out. SARIF export, OSV dependency intel, verified patches.",
  keywords: ["SAST", "taint analysis", "code security", "LLM", "multi-agent", "SARIF", "OSV", "DevSecOps"],
  openGraph: {
    title: "AegisCode — security review that argues with itself",
    description: "Deterministic taint analysis + an adversarial AI swarm that has to prove every claim.",
    type: "website",
  },
  twitter: { card: "summary_large_image" },
};

export const viewport: Viewport = {
  themeColor: "#08090a",
  colorScheme: "dark",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} ${instrumentSerif.variable} antialiased`}>
      <body className="grain min-h-dvh">
        <div className="backdrop" aria-hidden />
        {children}
      </body>
    </html>
  );
}
