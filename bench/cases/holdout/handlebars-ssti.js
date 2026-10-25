// expect: AEG-TAINT-SSTI
app.post("/preview", (req, res) => {
  const tpl = Handlebars.compile(req.body.template);
  res.send(tpl({ user: req.user }));
});
