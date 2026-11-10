// expect: AEG-TAINT-SSRF
app.get("/proxy", async (req, res) => {
  const target = new URL(String(req.query.url));
  const upstream = await fetch(target.href);
  res.send(await upstream.text());
});
