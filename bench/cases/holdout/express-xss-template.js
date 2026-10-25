// expect: AEG-TAINT-XSS
app.get("/profile", (req, res) => {
  res.send(`<div class="bio">${req.query.bio}</div>`);
});
