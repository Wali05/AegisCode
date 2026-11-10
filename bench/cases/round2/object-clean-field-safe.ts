// expect: none
app.get("/", async (req, res) => {
  const cfg = { host: "api.internal.example", token: req.headers.authorization };
  const r = await fetch("https://" + cfg.host + "/v1/me");
  res.json(await r.json());
});
