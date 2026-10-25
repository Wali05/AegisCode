// expect: none
app.post("/login", async (req, res) => {
  const user = await Users.findOne({ username: String(req.body.username) });
  res.json({ ok: !!user });
});
