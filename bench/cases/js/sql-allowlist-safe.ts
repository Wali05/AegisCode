// expect: none
const SORTABLE = new Set(["created_at", "price"]);
app.get("/items", async (req, res) => {
  const col = String(req.query.sort);
  if (!SORTABLE.has(col)) return res.status(400).end();
  res.json(await db.query(`SELECT * FROM items ORDER BY ${col}`));
});
