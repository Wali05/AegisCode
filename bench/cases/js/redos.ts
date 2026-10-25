// expect: AEG-TAINT-REDOS
app.get("/filter", (req, res) => {
  const re = new RegExp(req.query.pattern as string);
  res.json(items.filter((i) => re.test(i.name)));
});
