// expect: none
app.post("/", (req, res) => {
  const ids = req.body.ids.map((x) => Number(x)).join(",");
  db.query(`DELETE FROM t WHERE id IN (${ids})`);
});
