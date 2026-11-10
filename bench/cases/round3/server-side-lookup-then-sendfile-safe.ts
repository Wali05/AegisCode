// expect: none
app.get("/files/:id", (req, res) => {
  const file = files.find((f) => f.id === req.params.id);
  if (!file) return res.status(404).end();
  res.sendFile(file.path);
});
