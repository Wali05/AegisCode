// expect: none
const SORTABLE = { name: "name", newest: "created_at DESC", price: "price_cents" };
app.get("/products", async (req, res) => {
  const order = SORTABLE[req.query.sort] ?? "id";
  res.json(await db.query("SELECT * FROM products ORDER BY " + order));
});
