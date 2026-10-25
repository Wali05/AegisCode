// expect: none
app.get("/profile", (req, res) => {
  res.send(`<div class="bio">${escapeHtml(req.query.bio)}</div>`);
});
