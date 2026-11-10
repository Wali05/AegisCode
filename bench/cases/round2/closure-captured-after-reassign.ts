// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  const q = req.query.q;
  setTimeout(() => { db.query("SELECT " + q); }, 10);
});
