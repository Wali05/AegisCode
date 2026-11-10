// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  const id = req.query.id;
  if (!/\d+/.test(id)) return res.sendStatus(400);
  db.query("SELECT * FROM t WHERE id = " + id);
});
