// expect: AEG-TAINT-SQL
app.post("/", (req, res) => {
  const ids = req.body.ids.join(",");
  db.query(`DELETE FROM t WHERE id IN (${ids})`);
});
