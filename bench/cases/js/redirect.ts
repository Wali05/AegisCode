// expect: AEG-TAINT-REDIRECT
app.get("/login/done", (req, res) => {
  res.redirect(req.query.returnTo as string);
});
