import Link from "next/link";
import { GithubIcon, Logo } from "./ui";

export const REPO_URL = "https://github.com/Wali05/AegisCode";

export function Nav() {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-bg/70 backdrop-blur-xl">
      <div className="mx-auto flex h-14 w-full max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5" aria-label="AegisCode home">
          <Logo className="size-6" />
          <span className="text-[15px] font-semibold tracking-tight">AegisCode</span>
          <span className="hidden rounded-md border border-line px-1.5 py-0.5 font-mono text-[10.5px] text-fg-3 sm:inline">v2</span>
        </Link>
        <nav className="flex items-center gap-1 text-[13px]">
          <Link href="/#how" className="hidden rounded-lg px-3 py-1.5 text-fg-2 hover:bg-s2 hover:text-fg sm:inline">
            How it works
          </Link>
          <Link href="/agents" className="rounded-lg px-3 py-1.5 text-fg-2 hover:bg-s2 hover:text-fg">
            For agents
          </Link>
          <Link href="/rules" className="rounded-lg px-3 py-1.5 text-fg-2 hover:bg-s2 hover:text-fg">
            Rules
          </Link>
          <a href={REPO_URL} target="_blank" rel="noreferrer" className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-fg-2 hover:bg-s2 hover:text-fg">
            <GithubIcon className="size-4" />
            <span className="hidden sm:inline">GitHub</span>
          </a>
        </nav>
      </div>
    </header>
  );
}

export function Footer() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-10 text-[12.5px] text-fg-3 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div className="flex items-center gap-2">
          <Logo className="size-4" />
          <span>AegisCode: security checks for code your AI wrote.</span>
        </div>
        <div className="flex gap-4">
          <Link href="/agents" className="hover:text-fg-2">
            Agent setup
          </Link>
          <Link href="/rules" className="hover:text-fg-2">
            Rule catalog
          </Link>
          <a href={`${REPO_URL}#readme`} className="hover:text-fg-2">
            Docs
          </a>
          <a href={REPO_URL} className="hover:text-fg-2">
            Source
          </a>
        </div>
      </div>
    </footer>
  );
}
