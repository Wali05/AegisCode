// expect: none
app.get("/page", async (req, res) => {
  const page = Number.parseInt(req.query.page, 10) || 1;
  res.json(await db.query("SELECT * FROM items LIMIT 20 OFFSET " + (page - 1) * 20));
});
