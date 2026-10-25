// expect: AEG-TAINT-SQL
app.get("/u", async (req, res) => {
  res.json(await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${req.query.email}'`));
});
