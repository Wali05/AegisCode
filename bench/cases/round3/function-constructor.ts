// expect: AEG-TAINT-CODE
app.get("/calc", (req, res) => {
  const fn = new Function("return " + req.query.expr);
  res.json({ value: fn() });
});
