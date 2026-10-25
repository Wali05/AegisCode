// expect: AEG-TAINT-SSRF
app.post("/preview", async (req, res) => {
  const page = await fetch(req.body.url);
  res.send(await page.text());
});
