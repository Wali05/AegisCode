// expect: none
app.post("/", (req, res) => {
  const ids = req.body.ids.map(Number).join(",");
  db.query(`DELETE FROM t WHERE id IN (${ids})`);
});
