// expect: none
app.get("/report", (req, res) => {
  const kind = req.query.kind;
  if (kind !== "daily" && kind !== "weekly" && kind !== "monthly") return res.status(400).end();
  exec(`./reports/${kind}.sh`);
  res.end();
});
