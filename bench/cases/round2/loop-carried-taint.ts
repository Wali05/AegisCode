// expect: AEG-TAINT-SQL
app.post("/", (req, res) => {
  let acc = "";
  for (const p of req.body.parts) { db.query("SELECT " + acc); acc = p; }
});
