// expect: AEG-TAINT-REDIRECT
app.get("/", (req, res) => {
  const next = req.query?.next ?? "/";
  res.redirect(next);
});
