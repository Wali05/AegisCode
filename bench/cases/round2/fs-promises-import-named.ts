// expect: AEG-TAINT-PATH
import { readFile } from "node:fs/promises";
export async function GET(request: Request) {
  const name = new URL(request.url).searchParams.get("name");
  return new Response(await readFile("./data/" + name));
}
