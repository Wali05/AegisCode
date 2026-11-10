// expect: none
app.get("/feed", async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  res.json(await db.query(`SELECT * FROM posts ORDER BY id DESC LIMIT ${limit} OFFSET ${offset}`));
});
