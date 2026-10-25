// expect: AEG-TAINT-REDIRECT
export async function GET(request: Request) {
  const next = new URL(request.url).searchParams.get("next");
  return NextResponse.redirect(next!);
}
