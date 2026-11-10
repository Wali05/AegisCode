// expect: none
app.get("/", async (req, res) => {
  const rows = await sequelize.query("select * from users where email = :email", { replacements: { email: req.query.email } });
  res.json(rows);
});
