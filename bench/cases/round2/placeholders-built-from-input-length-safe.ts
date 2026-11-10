// expect: none
app.post("/", (req, res) => {
  const ids = req.body.ids;
  const ph = ids.map(() => "?").join(",");
  db.query(`DELETE FROM t WHERE id IN (${ph})`, ids);
});
