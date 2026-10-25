// expect: none
app.get("/files/:name", (req, res) => {
  res.sendFile(path.basename(req.params.name), { root: "/srv/uploads" });
});
