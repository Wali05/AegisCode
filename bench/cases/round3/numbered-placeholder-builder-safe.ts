// expect: none
app.get("/users", async (req, res) => {
  const values: unknown[] = [];
  const where: string[] = [];
  if (req.query.name) {
    values.push(req.query.name);
    where.push(`name = $${values.length}`);
  }
  if (req.query.email) {
    values.push(req.query.email);
    where.push(`email = $${values.length}`);
  }
  const sql = "SELECT * FROM users" + (where.length ? " WHERE " + where.join(" AND ") : "");
  res.json((await pool.query(sql, values)).rows);
});
