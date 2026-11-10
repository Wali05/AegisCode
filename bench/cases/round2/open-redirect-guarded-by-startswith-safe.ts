// expect: none
app.get("/", (req, res) => {
  const next = String(req.query.next || "/");
  if (!next.startsWith("/") || next.startsWith("//")) return res.redirect("/");
  res.redirect(next);
});
