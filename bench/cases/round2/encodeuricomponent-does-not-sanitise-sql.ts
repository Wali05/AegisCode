// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  const name = encodeURIComponent(req.query.name);
  db.query("SELECT * FROM t WHERE name = '" + name + "'");
});
