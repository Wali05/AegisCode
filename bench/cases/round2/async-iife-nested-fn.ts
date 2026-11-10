// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  const run = async () => { await pool.query("SELECT " + req.query.c + " FROM t"); };
  run();
});
