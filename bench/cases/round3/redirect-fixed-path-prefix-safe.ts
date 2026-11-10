// expect: none
app.post("/users/:id/avatar", upload.single("avatar"), async (req, res) => {
  await saveAvatar(Number(req.params.id), req.file.buffer);
  res.redirect("/users/" + req.params.id);
});
