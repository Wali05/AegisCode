// expect: none
app.get("/", (req, res) => {
  const t = jwt.verify(req.headers.authorization, SECRET);
  res.json({ id: t.sub });
});
