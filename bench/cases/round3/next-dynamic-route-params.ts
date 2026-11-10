// expect: AEG-TAINT-SQL
import { NextResponse } from "next/server";
import { pool } from "@/lib/db";
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { rows } = await pool.query(`SELECT * FROM invoices WHERE id = '${id}'`);
  return NextResponse.json(rows[0] ?? null);
}
