// expect: none
const ALLOWED = new Set(["api.github.com", "api.stripe.com"]);
app.post("/proxy", async (req, res) => {
  const target = new URL(req.body.url);
  if (!ALLOWED.has(target.hostname)) return res.status(403).end();
  res.json(await (await fetch(target)).json());
});
