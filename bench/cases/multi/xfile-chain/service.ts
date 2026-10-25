import { run } from "./repo";
export async function search(q: string) {
  return run("SELECT * FROM docs WHERE body LIKE '%" + q + "%'");
}
