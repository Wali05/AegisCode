// expect: AEG-TAINT-NOSQL
app.post("/login", async (req, res) => {
  const user = await db.collection("users").findOne({ username: req.body.username, password: req.body.password });
  if (!user) return res.status(401).end();
  res.json({ id: user._id });
});
