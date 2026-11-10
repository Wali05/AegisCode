// expect: none
app.get("/", (req, res) => {
  const a = req.query.a; const b = req.query.b;
  if (isUuid(a) && isUuid(b)) { db.query("SELECT * FROM t WHERE a = '" + a + "' AND b='" + b + "'"); }
});
