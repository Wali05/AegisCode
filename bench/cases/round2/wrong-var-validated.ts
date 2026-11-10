// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  const a = req.query.a; const b = req.query.b;
  if (!/^\d+$/.test(a)) return res.sendStatus(400);
  db.query("SELECT * FROM t WHERE id = " + b);
});
