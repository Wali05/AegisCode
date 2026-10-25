// expect: none
app.get("/batch", async (req, res) => {
  const ids = String(req.query.ids).split(",").map(Number).filter(Number.isInteger);
  res.json(await db.query("SELECT * FROM t WHERE id IN (" + ids.join(",") + ")"));
});
