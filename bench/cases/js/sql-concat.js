// expect: AEG-TAINT-SQL
app.get("/users", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  res.json(rows);
});
