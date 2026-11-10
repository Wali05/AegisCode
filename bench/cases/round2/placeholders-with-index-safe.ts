// expect: none
app.post("/", (req, res) => {
  const ids = req.body.ids;
  const ph = ids.map((_, i) => "$" + (i + 1)).join(",");
  pool.query(`DELETE FROM t WHERE id IN (${ph})`, ids);
});
