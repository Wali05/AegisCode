// expect: AEG-TAINT-NOSQL
app.get("/", async (req, res) => {
  const u = await User.find({ $where: "this.name == '" + req.query.name + "'" });
  res.json(u);
});
