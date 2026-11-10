// expect: none
app.get("/", (req, res) => {
  let id = req.query.id;
  if (!isValidId(id)) { id = "0"; }
  db.query("SELECT * FROM t WHERE id = " + id);
});
