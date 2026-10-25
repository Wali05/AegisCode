// expect: none
app.get("/u", async (req, res) => {
  res.json(await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${req.query.email}`);
});
