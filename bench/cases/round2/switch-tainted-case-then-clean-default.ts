// expect: AEG-TAINT-SQL
app.get("/", (req, res) => {
  let order;
  switch (req.query.mode) {
    case "raw": order = req.query.order; break;
    default: order = "id";
  }
  db.query("SELECT * FROM t ORDER BY " + order);
});
