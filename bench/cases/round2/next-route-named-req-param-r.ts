// expect: AEG-TAINT-CMD
export async function POST(r: Request) {
  const { cmd } = await r.json();
  return new Response(execSync(cmd));
}
