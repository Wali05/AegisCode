// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  const where = req.query.f ? "WHERE f = '" + req.query.f + "'" : "";
  db.query("SELECT * FROM t " + where);
});
