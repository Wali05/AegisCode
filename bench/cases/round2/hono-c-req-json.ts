// expect: AEG-TAINT-SQL
app.post("/x", async (c) => {
  const body = await c.req.json();
  const rows = await db.query("SELECT * FROM t WHERE name = '" + body.name + "'");
  return c.json(rows);
});
