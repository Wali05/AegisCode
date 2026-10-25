// expect: AEG-TAINT-SSRF
app.post("/proxy", async (req, res) => {
  const url = req.body.url;
  if (!url.startsWith("https://")) return res.status(400).end();
  res.json(await (await fetch(url)).json());
});
