// expect: AEG-TAINT-NOSQL
app.post("/login", async (req, res) => {
  const user = await Users.findOne({ username: req.body.username, password: req.body.password });
  res.json({ ok: !!user });
});
