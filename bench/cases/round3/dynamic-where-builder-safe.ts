// expect: none
app.get("/users", async (req, res) => {
  const params = [];
  let sql = "SELECT * FROM users WHERE 1=1";
  if (req.query.name) {
    sql += " AND name = ?";
    params.push(req.query.name);
  }
  if (req.query.role) {
    sql += " AND role = ?";
    params.push(req.query.role);
  }
  res.json(await db.query(sql, params));
});
