// expect: none
app.get("/search", async (req, res) => {
  res.json(await db.query(sql`SELECT * FROM items WHERE title ILIKE ${"%" + req.query.q + "%"}`));
});
