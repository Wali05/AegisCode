// expect: AEG-TAINT-SSRF
app.get("/", async (req, res) => {
  const u = new URL(req.query.u);
  if (!u.hostname.endsWith("example.com")) return res.status(400).end();
  await fetch(u);
});
