// expect: none
app.get("/", (req, res) => {
  res.send("<h1>" + escapeHtml(req.query.name) + "</h1>");
});
