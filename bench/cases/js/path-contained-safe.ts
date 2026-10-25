// expect: none
const ROOT = path.resolve("uploads");
app.get("/files/:name", (req, res) => {
  const file = path.resolve(ROOT, req.params.name);
  if (!file.startsWith(ROOT + path.sep)) return res.status(400).end();
  res.sendFile(file);
});
