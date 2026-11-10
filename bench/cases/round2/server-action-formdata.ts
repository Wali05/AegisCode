// expect: AEG-TAINT-SQL
"use server";
import { db } from "./db";
export async function rename(formData: FormData) {
  const name = formData.get("name");
  await db.query("UPDATE t SET name = '" + name + "'");
}
