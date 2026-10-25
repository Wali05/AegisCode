// expect: AEG-TAINT-DESER
app.post("/import", (req, res) => {
  const config = yaml.load(req.body.config);
  res.json(config);
});
