// expect: AEG-TAINT-SQL
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id");
  return Response.json(await sql.unsafe(`SELECT * FROM posts WHERE id = ${id}`));
}
