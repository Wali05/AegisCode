// expect: AEG-TAINT-SSRF
app.get("/fetch", async (c) => {
  const target = c.req.query("url");
  return c.text(await (await fetch(target)).text());
});
