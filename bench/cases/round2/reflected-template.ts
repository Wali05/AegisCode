// expect: AEG-TAINT-XSS
app.get("/", (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});
