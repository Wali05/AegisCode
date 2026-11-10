// expect: AEG-TAINT-SSRF
app.get("/", async (req, res) => {
  const u = req.query.u;
  if (!u.includes("example.com")) return res.status(400).end();
  const r = await fetch(u);
  res.send(await r.text());
});
