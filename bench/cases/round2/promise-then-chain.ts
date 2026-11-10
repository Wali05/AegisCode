// expect: AEG-TAINT-SSRF
app.get("/", (req, res) => {
  getUser(req.query.id).then((u) => res.send(u));
  fetch(req.query.u).then((r) => r.text()).then((t) => res.send(t));
});
