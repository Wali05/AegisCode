// expect: AEG-TAINT-SSRF
app.get("/", async (req, res) => {
  const cfg = { host: req.query.host, token: "x" };
  const r = await fetch("https://" + cfg.host + "/v1/me");
  res.json(await r.json());
});
