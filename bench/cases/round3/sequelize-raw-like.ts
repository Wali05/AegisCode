// expect: AEG-TAINT-SQL
app.get("/search", async (req, res) => {
  const [rows] = await sequelize.query(`SELECT id, name FROM products WHERE name LIKE '%${req.query.q}%'`);
  res.json(rows);
});
