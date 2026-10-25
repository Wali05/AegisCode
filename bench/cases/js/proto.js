// expect: AEG-TAINT-PROTO
app.post("/settings", (req, res) => {
  const { section, key, value } = req.body;
  settings[section][key] = value;
  res.end();
});
