// expect: AEG-TAINT-REDIRECT
import { NextResponse, type NextRequest } from "next/server";
export function middleware(req: NextRequest) {
  const from = req.nextUrl.searchParams.get("from");
  if (from) return NextResponse.redirect(new URL(from, req.url));
  return NextResponse.next();
}
