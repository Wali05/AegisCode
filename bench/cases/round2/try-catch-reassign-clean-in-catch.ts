// expect: AEG-TAINT-SSRF
app.get("/", async (req, res) => {
  let u = req.query.url;
  try { await check(u); } catch (e) { u = "https://example.com"; }
  await fetch(u);
});
