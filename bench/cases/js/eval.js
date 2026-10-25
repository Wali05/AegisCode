// expect: AEG-TAINT-CODE
app.post("/calc", (req, res) => {
  res.json({ result: eval(req.body.expression) });
});
