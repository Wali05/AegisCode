// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  let sql;
  if (!req.query.raw) { sql = "SELECT * FROM t"; } else { sql = "SELECT * FROM t WHERE " + req.query.raw; }
  db.query(sql);
});
