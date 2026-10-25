import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono, Instrument_Serif } from "next/font/google";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });
const instrumentSerif = Instrument_Serif({ variable: "--font-instrument-serif", subsets: ["latin"], weight: "400", style: ["normal", "italic"] });

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000"),
  title: {
    default: "AegisCode: security checks for code your AI wrote",
    template: "%s · AegisCode",
  },
  description:
    "Traces untrusted input across files, catches packages AI made up, and writes fixes it re-verifies. Runs inside coding agents over MCP, as a pre-commit hook, in CI and on the web.",
  keywords: ["SAST", "taint analysis", "AI code security", "MCP", "slopsquatting", "coding agents", "SARIF", "DevSecOps"],
  openGraph: {
    title: "AegisCode: security checks for code your AI wrote",
    description: "Cross-file taint analysis, a package check for hallucinated dependencies, and verified fixes — inside your coding agent, before every commit, and in CI.",
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
