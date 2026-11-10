// expect: AEG-TAINT-CMD
app.get("/", (req, res) => {
  spawn("sh", ["-c", "ls " + req.query.d]);
});
