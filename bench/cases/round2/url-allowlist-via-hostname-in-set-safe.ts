// expect: none
const ALLOWED = new Set(["a.example", "b.example"]);
app.get("/", async (req, res) => {
  const u = new URL(req.query.u);
  if (!ALLOWED.has(u.hostname)) return res.status(400).end();
  const r = await fetch(u);
  res.send(await r.text());
});
