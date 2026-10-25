// expect: none
app.post("/calc", (req, res) => {
  const data = JSON.parse(req.body.payload);
  res.json({ keys: Object.keys(data) });
});
