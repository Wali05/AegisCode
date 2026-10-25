// expect: none
app.get("/orders", async (req, res) => {
  const limit = Number(req.query.limit ?? 20);
  res.json(await db.query(`SELECT * FROM orders LIMIT ${limit}`));
});
