// expect: AEG-TAINT-SQL
app.get("/users", async (req, res) => {
  const users = await dataSource
    .getRepository(User)
    .createQueryBuilder("user")
    .where(`user.name = '${req.query.name}'`)
    .getMany();
  res.json(users);
});
