// expect: none
app.get("/", (req, res) => {
  res.send({ echo: req.query.q });
  res.json({ echo: req.query.q });
});
