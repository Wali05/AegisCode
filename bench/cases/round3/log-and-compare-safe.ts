// expect: none
app.post("/login", async (req, res) => {
  console.log("login attempt for " + req.body.email);
  const user = await User.findOne({ email: String(req.body.email) });
  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) return res.status(401).end();
  res.json({ ok: true });
});
