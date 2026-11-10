// expect: AEG-TAINT-SQL
app.get("/", async (req, res) => {
  const rows = await knex.raw(`select * from users where email = '${req.query.email}'`);
  res.json(rows);
});
