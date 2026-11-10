// expect: AEG-TAINT-CMD
app.post("/", (req, res) => {
  const items = req.body.items;
  for (let i = 0; i < items.length; i++) {
    exec("rm " + items[i]);
  }
});
