// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  let a = req.query.a;
  if (!/^\d+$/.test(a)) return res.sendStatus(400);
  a = req.query.b;
  db.query("SELECT * FROM t WHERE id = " + a);
});
