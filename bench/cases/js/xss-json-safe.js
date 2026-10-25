// expect: none
app.get("/hello", (req, res) => {
  res.json({ greeting: "Hello " + req.query.name });
});
