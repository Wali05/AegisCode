// expect: AEG-TAINT-CMD
app.get("/", (req, res) => {
  const f = path.basename(req.query.f);
  exec("convert " + f + " out.png");
});
